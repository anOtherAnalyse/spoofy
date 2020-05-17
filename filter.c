#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <filter.h>
#include <protocols.h>

int ethercmp(uint8_t* ether_1, uint8_t* ether_2) {
  return (*((uint32_t*)ether_1) == *((uint32_t*)ether_2)) && (*((uint16_t*)(ether_1+4)) == *((uint16_t*)(ether_2+4)));
}

int addSrcIp(struct rule_node* rule, uint32_t ip) {
  uint16_t ether_type = 0x8;
  if(rule->type == ETHER_TYPE_TOK && !memcmp(rule->value, (uint8_t*)(&ether_type), 2)) { // ip
    struct rule_node* ip_rule = malloc(sizeof(struct rule_node));
    if(!ip_rule) {
      perror("malloc");
      return 1;
    }
    ip_rule->type = IP_ADDR_DST_TOK | NEGATION_TERM;
    memcpy(ip_rule->value, (uint8_t*)(&ip), 4);
    ip_rule->next = 0;
    ip_rule->child = rule->child;
    rule->child = ip_rule;
  } else {
    if(rule->next) addSrcIp(rule->next, ip);
    if(rule->child) addSrcIp(rule->child, ip);
  }
  return 0;
}

/* **************************
 * Filter rule create & apply
 * ************************** */

int parseRule(char* rule, struct rule_node** result) {
  struct term* rule_exp = NULL;
  struct flattened_rule* flat_rule = NULL;

  if(parseE(&rule, &rule_exp)) return 1;

  // printExp(rule_exp);

  if(flattenRule(rule_exp, &flat_rule)) return 1;
  freeExp(rule_exp);

  // printFlatRule(flat_rule);

  *result = NULL;
  while(flat_rule) {
    if(inflateRule(&(flat_rule->flat_rule), result)) return 1;
    flat_rule = flat_rule->next;
  }

  freeLinkedFlatRules(flat_rule);

  return 0;
}

int applyRule(struct rule_node* rule, struct packet_layers* packet) {
  int result, negation = ((rule->type & NEGATION_TERM) != 0);
  switch(rule->type & 0x7f) {
    case ETHER_ADDR_SRC_TOK:
      result = ethercmp(rule->value, packet->ether_src);
      break;
    case ETHER_ADDR_DST_TOK:
      result = ethercmp(rule->value, packet->ether_dst);
      break;
    case ETHER_TYPE_TOK:
      result = (*((uint16_t*)rule->value) == *((uint16_t*)packet->ether_type));
      break;
    case IP_ADDR_SRC_TOK:
      result = *((uint32_t*)rule->value) == *((uint32_t*)packet->ip_src);
      break;
    case IP_ADDR_DST_TOK:
      result = *((uint32_t*)rule->value) == *((uint32_t*)packet->ip_dst);
      break;
    case PROTOCOL_TOK:
      result = packet->protocol[0] == rule->value[0];
      break;
    case PORT_SRC_TOK:
      result = *((uint16_t*)packet->port_src) == *((uint16_t*)rule->value);
      break;
    case PORT_DST_TOK:
      result = *((uint16_t*)packet->port_dst) == *((uint16_t*)rule->value);
  }
  result = (result + negation) % 2; // apply negation

  if(result && rule->child) { // so far so good
    result = applyRule(rule->child, packet);
  }

  if(result) return 1;

  if(rule->next) { // try other possibilities
    return applyRule(rule->next, packet);
  }

  return 0;
}

void freeRule(struct rule_node* rule) {
  if(rule) {
    freeRule(rule->child);
    freeRule(rule->next);
    free(rule);
  }
}

/* *****************************************
 * Inflated rule - Final rule transformation
 * ***************************************** */

int inflateRule(struct raw_filter* rule, struct rule_node** result) {
  int j, i;
  for(j = 0; j < 8; j ++) {
    uint8_t type;
    uint16_t addr_len;
    struct address_list* addr;
    switch(j) {
      case 0:
        type = ETHER_ADDR_SRC_TOK | (rule->ether_src_neg << 7);
        addr_len = 6;
        addr = &(rule->ether_src);
        break;
      case 1:
        type = ETHER_ADDR_DST_TOK | (rule->ether_dst_neg << 7);
        addr_len = 6;
        addr = &(rule->ether_dst);
        break;
      case 2:
        type = ETHER_TYPE_TOK | (rule->ether_type_neg << 7);
        addr_len = 2;
        addr = &(rule->ether_type);
        break;
      case 3:
        type = IP_ADDR_SRC_TOK | (rule->protocol_src_neg << 7);
        addr_len = 4;
        addr = &(rule->protocol_src);
        break;
      case 4:
        type = IP_ADDR_DST_TOK | (rule->protocol_dst_neg << 7);
        addr_len = 4;
        addr = &(rule->protocol_dst);
        break;
      case 5:
        type = PROTOCOL_TOK | (rule->protocol_type_neg << 7);
        addr_len = 1;
        addr = &(rule->protocol_type);
        break;
      case 6:
        type = PORT_SRC_TOK | (rule->transport_src_neg << 7);
        addr_len = 2;
        addr = &(rule->transport_src);
        break;
      case 7:
        type = PORT_DST_TOK | (rule->transport_dst_neg << 7);
        addr_len = 2;
        addr = &(rule->transport_dst);
    }
    if(addr->addr == NULL) continue;

    for(i = 0; i < addr->length; i ++) {

      while(*result && ((*result)->type != type || memcmp(addr->addr + (i * addr_len), (*result)->value, addr_len)))
        result = &((*result)->next);

      if(*result == NULL) { // then alloc new struct
        if(!(*result = malloc(sizeof(struct rule_node)))) {
          perror("malloc");
          return 1;
        }
        memset(*result, 0, sizeof(struct rule_node));
        (*result)->type = type;
        memcpy((*result)->value, addr->addr + (i * addr_len), addr_len);
      }

      result = &((*result)->child);
    }

  }
  return 0;
}

void printRule(struct rule_node* rule, uint8_t shift) {
  int i;
  for(i = 0; i < shift; i ++) printf("  ");
  printf("| ");
  if(rule->type & NEGATION_TERM) printf("not ");
  switch(rule->type & 0x7f) {
    case ETHER_ADDR_SRC_TOK:
      printf("ether src %x:%x:%x:%x:%x:%x\n", rule->value[0], rule->value[1], rule->value[2], rule->value[3], rule->value[4], rule->value[5]);
      break;
    case ETHER_ADDR_DST_TOK:
      printf("ether dst %x:%x:%x:%x:%x:%x\n", rule->value[0], rule->value[1], rule->value[2], rule->value[3], rule->value[4], rule->value[5]);
      break;
    case IP_ADDR_SRC_TOK:
      printf("src %u.%u.%u.%u\n", rule->value[0], rule->value[1], rule->value[2], rule->value[3]); break;
    case IP_ADDR_DST_TOK:
      printf("dst %u.%u.%u.%u\n", rule->value[0], rule->value[1], rule->value[2], rule->value[3]); break;
    case PORT_SRC_TOK: printf("port src %hu\n", ntohs(*((uint16_t*)rule->value))); break;
    case PORT_DST_TOK: printf("port dst %hu\n", ntohs(*((uint16_t*)rule->value))); break;
    case ETHER_TYPE_TOK: printf("ether type 0x%x\n", ntohs(*((uint16_t*)rule->value))); break;
    case PROTOCOL_TOK: printf("protocol %u\n", rule->value[0]);
  }
  if(rule->child) {
    printRule(rule->child, shift + 1);
  }
  if(rule->next) {
    printRule(rule->next, shift);
  }
}

/* *************************************************************************
 * Flattened rule, from a token tree to a list of possibilities (raw_filter)
 * ************************************************************************* */

int allocAddrList(struct address_list* addrs, uint8_t* addr, uint16_t length) {
  addrs->addr = realloc(addrs->addr, length * (addrs->length + 1));
  if(!addrs->addr) {
    perror("realloc");
    return 1;
  }
  memcpy(addrs->addr + (length * addrs->length), addr, length);
  addrs->length += 1;
  return 0;
}

int isInAddrList(struct address_list* addrs, uint8_t* addr, uint16_t length) {
  int i;
  for(i = 0; i < addrs->length; i ++) {
    if(!memcmp(addr, addrs->addr + (i*length), length)) return 1;
  }
  return 0;
}

int copyAddr(struct address_list* dst, struct address_list* src, uint16_t length) {
  if(!(dst->addr = malloc(length * src->length))) {
    perror("malloc");
    return 1;
  }
  memcpy(dst->addr, src->addr, length * src->length);
  dst->length = src->length;
  return 0;
}

int mergeAdressesLists(struct address_list* a1, uint8_t a1_neg,
  struct address_list* a2, uint8_t a2_neg, struct address_list* result, uint16_t addr_len) {
    if(a1->addr || a2->addr) {
      if(!a1->addr) {
        if(copyAddr(result, a2, addr_len)) return 1;
      } else if(!a2->addr) {
        if(copyAddr(result, a1, addr_len)) return 1;
      } else {
        switch(a1_neg + 2*a2_neg) {
            case 0:
              if(memcmp(a1->addr, a2->addr, addr_len)) return 1;
              if(copyAddr(result, a1, addr_len)) return 1;
              break;
            case 1:
              if(isInAddrList(a1, a2->addr, addr_len)) return 1;
              if(copyAddr(result, a2, addr_len)) return 1;
              break;
            case 2:
              if(isInAddrList(a2, a1->addr, addr_len)) return 1;
              if(copyAddr(result, a1, addr_len)) return 1;
              break;
            case 3:
              {
                if(copyAddr(result, a1, addr_len)) return 1;
                int i;
                for(i = 0; i < a2->length; i ++)
                  if(allocAddrList(result, a2->addr + (i*addr_len), addr_len)) return 1;
              }
        }
      }
    } else memset(result, 0, sizeof(struct address_list));
    return 0;
}

int mergeRawFilters(struct raw_filter* r1, struct raw_filter* r2, struct raw_filter* result) {
  int ret =
    mergeAdressesLists(&(r1->ether_src), r1->ether_src_neg, &(r2->ether_src), r2->ether_src_neg, &(result->ether_src), 6)
    + mergeAdressesLists(&(r1->ether_dst), r1->ether_dst_neg, &(r2->ether_dst), r2->ether_dst_neg, &(result->ether_dst), 6)
    + mergeAdressesLists(&(r1->ether_type), r1->ether_type_neg, &(r2->ether_type), r2->ether_type_neg, &(result->ether_type), 2)
    + mergeAdressesLists(&(r1->protocol_src), r1->protocol_src_neg, &(r2->protocol_src), r2->protocol_src_neg, &(result->protocol_src), 4)
    + mergeAdressesLists(&(r1->protocol_dst), r1->protocol_dst_neg, &(r2->protocol_dst), r2->protocol_dst_neg, &(result->protocol_dst), 4)
    + mergeAdressesLists(&(r1->protocol_type), r1->protocol_type_neg, &(r2->protocol_type), r2->protocol_type_neg, &(result->protocol_type), 1)
    + mergeAdressesLists(&(r1->transport_src), r1->transport_src_neg, &(r2->transport_src), r2->transport_src_neg, &(result->transport_src), 2)
    + mergeAdressesLists(&(r1->transport_dst), r1->transport_dst_neg, &(r2->transport_dst), r2->transport_dst_neg, &(result->transport_dst), 2);
  if(ret) return 1;
  result->negation = r1->negation & r2->negation; // manage the NOT
  return 0;
}

int allocLinkedFlatRules(struct flattened_rule** result, uint8_t number) {
  int i;
  for(i = 0; i < number; i ++) {
    if(!((*result) = malloc(sizeof(struct flattened_rule)))) {
      perror("malloc");
      return 1;
    }
    memset(&((*result)->flat_rule), 0, sizeof(struct raw_filter));
    (*result)->flat_rule.negation = 0xff; // default negation
    result = &((*result)->next);
  }
  *result = NULL; // end linked list
  return 0;
}

void freeLinkedFlatRules(struct flattened_rule* list) {
  struct flattened_rule* current;
  while(list) {
    current = list;
    list = list->next;
    free(current->flat_rule.ether_src.addr);
    free(current->flat_rule.ether_dst.addr);
    free(current->flat_rule.protocol_src.addr);
    free(current->flat_rule.protocol_dst.addr);
    free(current->flat_rule.transport_src.addr);
    free(current->flat_rule.transport_dst.addr);
    free(current);
  }
}

int flattenRule(struct term* node, struct flattened_rule** result) {
  int i;
  uint8_t negation = (node->type & NEGATION_TERM) ? 1 : 0, protocol = 0;
  uint16_t ether_type = 0x0008;
  if(node->type & UNARY_TERM) {
    struct unary_term* uterm = (struct unary_term*)node;
    if(allocLinkedFlatRules(result, 1)) return 1;
    switch(uterm->token.type) {
      case ETHER_TOK:
        if(negation) {
          if(allocAddrList(&((*result)->flat_rule.ether_src), (uint8_t*)uterm->token.value, 6)) return 1;
          if(allocAddrList(&((*result)->flat_rule.ether_dst), (uint8_t*)uterm->token.value, 6)) return 1;
        } else {
          if(allocLinkedFlatRules(&((*result)->next), 1)) return 1;
          for(i = 0;i < 2; i ++) {
            struct address_list* addr = i ? &((*result)->flat_rule.ether_dst) : &((*result)->flat_rule.ether_src);
            if(allocAddrList(addr, (uint8_t*)uterm->token.value, 6)) return 1;
            (*result)->flat_rule.negation &= ~((uint8_t)i+1);
            result = &((*result)->next);
          }
        }
        break;
      case ETHER_ADDR_SRC_TOK:
        if(allocAddrList(&((*result)->flat_rule.ether_src), (uint8_t*)uterm->token.value, 6)) return 1;
        (*result)->flat_rule.ether_src_neg = negation;
        break;
      case ETHER_ADDR_DST_TOK:
        if(allocAddrList(&((*result)->flat_rule.ether_dst), (uint8_t*)uterm->token.value, 6)) return 1;
        (*result)->flat_rule.ether_dst_neg = negation;
        break;
      case ARP_TOK:
        ether_type += 0x0600;
      case IP_TOK:
        if(allocAddrList(&((*result)->flat_rule.ether_type), (uint8_t*)&ether_type, 2)) return 1;
        (*result)->flat_rule.ether_type_neg = negation;
        break;
      case HOST_TOK:
        if(negation) {
          if(allocAddrList(&((*result)->flat_rule.ether_type), (uint8_t*)&ether_type, 2)) return 1;
          if(allocAddrList(&((*result)->flat_rule.protocol_src), (uint8_t*)uterm->token.value, 4)) return 1;
          if(allocAddrList(&((*result)->flat_rule.protocol_dst), (uint8_t*)uterm->token.value, 4)) return 1;
          (*result)->flat_rule.ether_type_neg = 0;
        } else {
          if(allocLinkedFlatRules(&((*result)->next), 1)) return 1;
          for(i = 0;i < 2; i ++) {
            struct address_list* addr = i ? &((*result)->flat_rule.protocol_dst) : &((*result)->flat_rule.protocol_src);
            if(allocAddrList(&((*result)->flat_rule.ether_type), (uint8_t*)&ether_type, 2)) return 1;
            if(allocAddrList(addr, (uint8_t*)uterm->token.value, 4)) return 1;
            (*result)->flat_rule.negation &= ~((uint8_t)1 << (i+3)) & 0xfb;
            result = &((*result)->next);
          }
        }
        break;
      case IP_ADDR_SRC_TOK:
        if(allocAddrList(&((*result)->flat_rule.ether_type), (uint8_t*)&ether_type, 2)) return 1;
        if(allocAddrList(&((*result)->flat_rule.protocol_src), (uint8_t*)uterm->token.value, 4)) return 1;
        (*result)->flat_rule.ether_type_neg = 0;
        (*result)->flat_rule.protocol_src_neg = negation;
        break;
      case IP_ADDR_DST_TOK:
        if(allocAddrList(&((*result)->flat_rule.ether_type), (uint8_t*)&ether_type, 2)) return 1;
        if(allocAddrList(&((*result)->flat_rule.protocol_dst), (uint8_t*)uterm->token.value, 4)) return 1;
        (*result)->flat_rule.ether_type_neg = 0;
        (*result)->flat_rule.protocol_dst_neg = negation;
        break;
      case UDP_TOK:
        protocol += 11;
      case TCP_TOK:
        protocol += 5;
      case ICMP_TOK:
        protocol += 1;
        if(allocAddrList(&((*result)->flat_rule.ether_type), (uint8_t*)&ether_type, 2)) return 1;
        if(allocAddrList(&((*result)->flat_rule.protocol_type), &protocol, 1)) return 1;
        (*result)->flat_rule.ether_type_neg = 0;
        (*result)->flat_rule.protocol_type_neg = negation;
        break;
      case PORT_SRC_TOK:
        if(allocLinkedFlatRules(&((*result)->next), 1)) return 1;
        for(i = 0; i < 2; i ++) {
          if(allocAddrList(&((*result)->flat_rule.ether_type), (uint8_t*)&ether_type, 2)) return 1;
          if(allocAddrList(&((*result)->flat_rule.transport_src), (uint8_t*)uterm->token.value, 2)) return 1;
          protocol = (i ? 17 : 6);
          if(allocAddrList(&((*result)->flat_rule.protocol_type), &protocol, 1)) return 1;
          (*result)->flat_rule.negation &= 0xdb;
          (*result)->flat_rule.transport_src_neg = negation;
          result = &((*result)->next);
        }
        break;
      case PORT_DST_TOK:
        if(allocLinkedFlatRules(&((*result)->next), 1)) return 1;
        for(i = 0; i < 2; i ++) {
          if(allocAddrList(&((*result)->flat_rule.ether_type), (uint8_t*)&ether_type, 2)) return 1;
          if(allocAddrList(&((*result)->flat_rule.transport_dst), (uint8_t*)uterm->token.value, 2)) return 1;
          protocol = (i ? 17 : 6);
          if(allocAddrList(&((*result)->flat_rule.protocol_type), &protocol, 1)) return 1;
          (*result)->flat_rule.negation &= 0xdb;
          (*result)->flat_rule.transport_dst_neg = negation;
          result = &((*result)->next);
        }
        break;
      case PORT_TOK:
      if(negation) {
        if(allocLinkedFlatRules(&((*result)->next), 1)) return 1;
        for(i = 0; i < 2; i ++) {
          if(allocAddrList(&((*result)->flat_rule.ether_type), (uint8_t*)&ether_type, 2)) return 1;
          protocol = (i ? 17 : 6);
          if(allocAddrList(&((*result)->flat_rule.protocol_type), &protocol, 1)) return 1;
          if(allocAddrList(&((*result)->flat_rule.transport_src), (uint8_t*)uterm->token.value, 2)) return 1;
          if(allocAddrList(&((*result)->flat_rule.transport_dst), (uint8_t*)uterm->token.value, 2)) return 1;
          (*result)->flat_rule.negation &= 0xdb;
          result = &((*result)->next);
        }
      } else {
        if(allocLinkedFlatRules(&((*result)->next), 3)) return 1;
        for(i = 0; i < 4; i ++) {
          struct address_list* addr = (i % 2) ? &((*result)->flat_rule.transport_dst) : &((*result)->flat_rule.transport_src);
          if(allocAddrList(&((*result)->flat_rule.ether_type), (uint8_t*)&ether_type, 2)) return 1;
          protocol = (i < 2 ? 17 : 6);
          if(allocAddrList(&((*result)->flat_rule.protocol_type), &protocol, 1)) return 1;
          if(allocAddrList(addr, (uint8_t*)uterm->token.value, 2)) return 1;
          (*result)->flat_rule.negation &= ~((uint8_t)1 << (6 + (i%2))) & 0xdb;
          result = &((*result)->next);
        }
      }
    }
  } else {
    struct binary_term* bterm = (struct binary_term*)node;
    if(negation) { // process negation
      bterm->exp_left->type ^= NEGATION_TERM;
      bterm->exp_right->type ^= NEGATION_TERM;
    }

    if((bterm->opp == OPP_OR) ^ negation) { // or, just concat
      if(flattenRule(bterm->exp_left, result)) return 1;
      while(*result != NULL) result = &((*result)->next);
      if(flattenRule(bterm->exp_right, result)) return 1;
    } else { // and, cartesian product
      struct flattened_rule *rule_left, *rule_right, *current_left, *current_right;
      if(flattenRule(bterm->exp_left, &rule_left)) return 1;
      if(flattenRule(bterm->exp_right, &rule_right)) return 1;

      i = 0;

      current_left = rule_left;
      while(current_left) {
        current_right = rule_right;
        while(current_right) {
          struct raw_filter concat;
          if(! mergeRawFilters(&(current_left->flat_rule), &(current_right->flat_rule), &concat)) {
            if(allocLinkedFlatRules(result, 1)) return 1;
            (*result)->flat_rule = concat;
            result = &((*result)->next);
            i ++;
          }
          current_right = current_right->next;
        }

        current_left = current_left->next;
      }

      freeLinkedFlatRules(rule_left);
      freeLinkedFlatRules(rule_right);

      if(!i) {
        fprintf(stderr, "Error: filter expression rejects all packets\n");
        return 1;
      }
    }
  }
  return 0;
}

void printAddrList(struct address_list* list, uint8_t neg, uint16_t length) {
  if(neg) printf("not ");
  int i;
  for(i = 0; i < list->length; i ++) {
    uint8_t* current = list->addr + (i*length);
    switch(length) {
      case 1:
        printf("%u", current[0]); break;
      case 2:
        printf("%hu (0x%x)", ntohs(*((uint16_t*)current)), ntohs(*((uint16_t*)current))); break;
      case 4:
        printf("%u.%u.%u.%u", current[0], current[1], current[2], current[3]); break;
      case 6:
        printf("%x:%x:%x:%x:%x:%x", current[0], current[1], current[2], current[3], current[4], current[5]); break;
    }
    if(i + 1 < list->length) printf(" and ");
  }
  printf("\n");
}

void printFlatRule(struct flattened_rule* rule) {
  printf("\033[31mCurrent filter matches:\033[0m\n");
  while(rule) {
    if(rule->flat_rule.ether_src.addr) {
      printf("ether_src: ");
      printAddrList(&(rule->flat_rule.ether_src), rule->flat_rule.ether_src_neg, 6);
    }
    if(rule->flat_rule.ether_dst.addr) {
      printf("ether_dst: ");
      printAddrList(&(rule->flat_rule.ether_dst), rule->flat_rule.ether_dst_neg, 6);
    }
    if(rule->flat_rule.ether_type.addr) {
      printf("ether_type: ");
      printAddrList(&(rule->flat_rule.ether_type), rule->flat_rule.ether_type_neg, 2);
    }
    if(rule->flat_rule.protocol_src.addr) {
      printf("protocol_src: ");
      printAddrList(&(rule->flat_rule.protocol_src), rule->flat_rule.protocol_src_neg, 4);
    }
    if(rule->flat_rule.protocol_dst.addr) {
      printf("protocol_dst: ");
      printAddrList(&(rule->flat_rule.protocol_dst), rule->flat_rule.protocol_dst_neg, 4);
    }
    if(rule->flat_rule.protocol_type.addr) {
      printf("protocol_type: ");
      printAddrList(&(rule->flat_rule.protocol_type), rule->flat_rule.protocol_type_neg, 1);
    }
    if(rule->flat_rule.transport_src.addr) {
      printf("transport_src: ");
      printAddrList(&(rule->flat_rule.transport_src), rule->flat_rule.transport_src_neg, 2);
    }
    if(rule->flat_rule.transport_dst.addr) {
      printf("transport_dst: ");
      printAddrList(&(rule->flat_rule.transport_dst), rule->flat_rule.transport_dst_neg, 2);
    }
    rule = rule->next;
    if(rule) printf(" -----\n");
  }
}

/* **********************************************************
 * Expression parsing, from string expression to a token tree
 * ********************************************************** */

void freeExp(struct term* rule) {
   if(rule->type & UNARY_TERM) {
     struct unary_term* uterm = (struct unary_term*) rule;
     if(uterm->token.length == 0) { // token.value was dynamically allocated
       free(uterm->token.value);
     }
     free(uterm);
   } else {
     struct binary_term* bterm = (struct binary_term*) rule;
     freeExp(bterm->exp_left);
     freeExp(bterm->exp_right);
     free(bterm);
   }
 }

int parseE(char** rule, struct term** result) {

  int ret;
  struct token tok;
  struct term *t1;

  if((ret = parseT(rule, &t1))) {
    if(ret == 2) fprintf(stderr, "Filter rule: Missing expression\n");
    return 1;
  }

  char* ccopy = *rule;
  if((ret = nextToken(&ccopy, &tok)) == 1) return 1;

  if(ret == 2 || (tok.type != OPP_OR && tok.type != OPP_AND)) { // unary expression
    *result = t1;
  } else { // binary expression

    *rule = ccopy;

    struct binary_term* bterm;
    if(!(bterm = malloc(sizeof(struct binary_term)))) {
      perror("malloc ");
      return 1;
    }
    bterm->type = BINARY_TERM;
    bterm->exp_left = t1;
    bterm->opp = tok.type;

    if((ret = parseE(rule, &(bterm->exp_right)))) return 1;

    *result = (struct term*) bterm;
  }

  return 0;
}

int parseT(char** rule, struct term** result) {

  int ret;
  struct token tok;
  if((ret = nextToken(rule, &tok))) return ret;

  if(tok.type == PAR_OPN) { // T -> ( E )

    if(parseE(rule, result)) return 1;

    if((ret = nextToken(rule, &tok))) {
      if(ret == 2 || tok.type != PAR_CLS) fprintf(stderr, "Filter rule: Unbalanced parenthesis\n");
      return 1;
    }
  } else if(tok.type == OPP_NOT) {
    if(parseT(rule, result)) return 1;
    (*result)->type ^= NEGATION_TERM;
  } else if(tok.type <= END_FILTER_TOK) { // Other rules
    if(!(*result = (struct term*)malloc(sizeof(struct unary_term)))) {
      perror("malloc ");
      return 1;
    }
    (*result)->type = UNARY_TERM;
    ((struct unary_term*)(*result))->token = tok;
  } else {
    fprintf(stderr, "Filter rule: syntax error\n");
    return 1;
  }

  return 0;
}

int nextToken(char** rule, struct token* token) {

  if(nextWord(rule, &(token->length))) return 2;
  token->value = *rule;
  *rule += token->length;

  // Select token type
  if(token->value[0] == '(') token->type = PAR_OPN;
  else if(token->value[0] == ')') token->type = PAR_CLS;
  else if(! strncmp(token->value, "not", MAX(token->length, 3)))token->type = OPP_NOT;
  else if(! strncmp(token->value, "and", MAX(token->length, 3)))token->type = OPP_AND;
  else if(! strncmp(token->value, "or", MAX(token->length, 2)))token->type = OPP_OR;
  else if(! strncmp(token->value, "arp", MAX(token->length, 3))) token->type = ARP_TOK;
  else if(! strncmp(token->value, "ip", MAX(token->length, 2))) token->type = IP_TOK;
  else if(! strncmp(token->value, "tcp", MAX(token->length, 3))) token->type = TCP_TOK;
  else if(! strncmp(token->value, "udp", MAX(token->length, 3))) token->type = UDP_TOK;
  else if(! strncmp(token->value, "icmp", MAX(token->length, 4))) token->type = ICMP_TOK;
  else if(! strncmp(token->value, "src", MAX(token->length, 3))
          || ! strncmp(token->value, "dst", MAX(token->length, 3))
          || ! strncmp(token->value, "host", MAX(token->length, 4)))
  {

    token->type = (token->value[0] == 's') ? IP_ADDR_SRC_TOK : (token->value[0] == 'd') ? IP_ADDR_DST_TOK : HOST_TOK;
    if(parseIPAddr(rule, token)) return 1;

  } else if(! strncmp(token->value, "ether", MAX(token->length, 5)) || ! strncmp(token->value, "port", MAX(token->length, 4))) {

    token->type = ((token->value[0] == 'e') ? ETHER_TOK : PORT_TOK);

    uint16_t length;
    char* ccopy = *rule;
    if(nextWord(&ccopy, &length)) {
      fprintf(stderr, "Filter rule: Missing address or etheir \"src\" or \"dst\" after %.*s\n", token->length, token->value);
      return 1;
    }

    if(! strncmp(ccopy, "src", MAX(length, 3)) || ! strncmp(ccopy, "dst", MAX(3, length))) {
      token->type += (ccopy[0] == 's') ? 1 : 2;
      *rule = ccopy + length;
    }

    if(token->type <= ETHER_ADDR_DST_TOK) {
      if(parseMACAddr(rule, token)) return 1;
    } else {
      if(parsePort(rule, token)) return 1;
    }

  } else {
    fprintf(stderr, "Filter rule: Unknown filter rule argument \"%.*s\"\n", token->length, token->value);
    return 1;
  }

  return 0;
}

int parseIPAddr(char** rule, struct token* token) {
  uint16_t length;
  if(nextWord(rule, &length)) {
    fprintf(stderr, "Filter rule: Expecting IP address\n");
    return 1;
  }

  struct in_addr** target = (struct in_addr**)(&(token->value));
  if(!(*target = malloc(sizeof(struct in_addr)))) {
    perror("malloc ");
    return 1;
  }
  if(! inet_aton(*rule, *target)) {
    fprintf(stderr, "Filter rule: Invalid IP address %.*s\n", length, *rule);
    return 1;
  }
  token->length = 0;
  *rule += length;

  return 0;
}

int parseMACAddr(char** rule, struct token* token) {
  uint16_t length;
  if(nextWord(rule, &length)) {
    fprintf(stderr, "Filter rule: Expecting MAC address\n");
    return 1;
  }

  if(!(token->value = malloc(6))) {
    perror("malloc ");
    return 1;
  }

  uint32_t tmp[6], i;
  if(sscanf(*rule, "%x:%x:%x:%x:%x:%x", tmp, tmp + 1, tmp + 2, tmp + 3, tmp + 4, tmp + 5) != 6) {
    fprintf(stderr, "Filter rule: Invalid MAC address \"%.*s\"\n", length, *rule);
    return 1;
  }
  for(i = 0; i < 6; i ++) token->value[i] = ((char*)(tmp + i))[0];
  token->length = 0;

  *rule += length;

  return 0;
}

int parsePort(char** rule, struct token* token) {
  uint16_t length;
  if(nextWord(rule, &length)) {
    fprintf(stderr, "Filter rule: Expecting port number\n");
    return 1;
  }

  if(!(token->value = malloc(2))) {
    perror("malloc ");
    return 1;
  }

  uint32_t tmp[6], i;
  if(sscanf(*rule, "%hu", (uint16_t*)(token->value)) != 1) {
    fprintf(stderr, "Filter rule: Invalid port number \"%.*s\"\n", length, *rule);
    return 1;
  }
  *((uint16_t*)(token->value)) = htons(*((uint16_t*)(token->value)));
  token->length = 0;

  *rule += length;

  return 0;
}

int nextWord(char** rule, uint16_t* length) {

  while((*rule)[0] == ' ' || (*rule)[0] == '\t')*rule += 1;

  if(!(*rule)[0])return 1;

  *length = 1;

  if((*rule)[0] == '(' || (*rule)[0] == ')') return 0;

  while((*rule)[*length] != '\0' && (*rule)[*length] != ' ' && (*rule)[*length] != '\t' && (*rule)[*length] != '(' && (*rule)[*length] != ')') *length += 1;

  return 0;
}

void printExp(struct term* rule) {
  printf("\033[31mRule expression:\033[0m ");
  __printExp(rule);
  printf("\n");
}

void __printExp(struct term* rule) {
  if(rule->type & NEGATION_TERM) printf("not ");
  if(rule->type & UNARY_TERM) {
    struct unary_term* uterm = (struct unary_term*) rule;
    switch(uterm->token.type) {
      case ARP_TOK: printf("arp"); break;
      case IP_TOK: printf("ip"); break;
      case TCP_TOK: printf("tcp"); break;
      case UDP_TOK: printf("udp"); break;
      case ICMP_TOK: printf("icmp"); break;
      case ETHER_TOK: printf("ether %x:%x:%x:%x:%x:%x", (uint8_t)uterm->token.value[0], (uint8_t)uterm->token.value[1], (uint8_t)uterm->token.value[2], (uint8_t)uterm->token.value[3], (uint8_t)uterm->token.value[4], (uint8_t)uterm->token.value[5]); break;
      case ETHER_ADDR_SRC_TOK: printf("ether src %x:%x:%x:%x:%x:%x", (uint8_t)uterm->token.value[0], (uint8_t)uterm->token.value[1], (uint8_t)uterm->token.value[2], (uint8_t)uterm->token.value[3], (uint8_t)uterm->token.value[4], (uint8_t)uterm->token.value[5]); break;
      case ETHER_ADDR_DST_TOK: printf("ether dst %x:%x:%x:%x:%x:%x", (uint8_t)uterm->token.value[0], (uint8_t)uterm->token.value[1], (uint8_t)uterm->token.value[2], (uint8_t)uterm->token.value[3], (uint8_t)uterm->token.value[4], (uint8_t)uterm->token.value[5]); break;
      case HOST_TOK: printf("host %u.%u.%u.%u", ((uint8_t*)uterm->token.value)[0], ((uint8_t*)uterm->token.value)[1], ((uint8_t*)uterm->token.value)[2], ((uint8_t*)uterm->token.value)[3]); break;
      case IP_ADDR_SRC_TOK: printf("src %u.%u.%u.%u", ((uint8_t*)uterm->token.value)[0], ((uint8_t*)uterm->token.value)[1], ((uint8_t*)uterm->token.value)[2], ((uint8_t*)uterm->token.value)[3]); break;
      case IP_ADDR_DST_TOK: printf("dst %u.%u.%u.%u", ((uint8_t*)uterm->token.value)[0], ((uint8_t*)uterm->token.value)[1], ((uint8_t*)uterm->token.value)[2], ((uint8_t*)uterm->token.value)[3]); break;
      case PORT_TOK: printf("port %u", ntohs(*((uint16_t*)uterm->token.value))); break;
      case PORT_SRC_TOK: printf("port src %u", ntohs(*((uint16_t*)uterm->token.value))); break;
      case PORT_DST_TOK: printf("port dst %u", ntohs(*((uint16_t*)uterm->token.value))); break;
      default: printf("???");
    }
  } else {
    struct binary_term* bterm = (struct binary_term*) rule;
    printf("(");
    __printExp(bterm->exp_left);
    switch(bterm->opp) {
      case OPP_OR: printf(" or "); break;
      case OPP_AND: printf(" and "); break;
      default: printf(" ??? ");
    }
    __printExp(bterm->exp_right);
    printf(")");
  }
}
