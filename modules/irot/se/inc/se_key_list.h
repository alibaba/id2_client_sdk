#ifndef _SE_KEY_LIST_H_
#define _SE_KEY_LIST_H_

#include "irot_hal.h"

#define ID2_CLIENT_KEY_NAME                "id2_key"
#define CTID_CLIENT_KEY_NAME               "ID2IntStr_01"

typedef struct _key_index_t {
    char *key_name;
    uint8_t key_id;
} key_index_t;

const key_index_t key_list[] = {
    {ID2_CLIENT_KEY_NAME, ID2_CLIENT_KEY_ID},
    {CTID_CLIENT_KEY_NAME, CTID_CLIENT_KEY_ID},
};

#endif /* _SE_KEY_LIST_H_ */

