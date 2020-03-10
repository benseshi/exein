/* Copyright 2019 Exein. All Rights Reserved.

Licensed under the GNU General Public License, Version 3.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.gnu.org/licenses/gpl-3.0.html

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/

#include <linux/types.h>
#include <linux/hashtable.h>
#define EXEIN_REG_DURATION		2500
#define EXEIN_PROT_REGISTRATION_ID	1
#define EXEIN_PROT_KEEPALIVE_ID		2
#define EXEIN_PROT_FEED_ID		3
#define EXEIN_PROT_BLOCK_ID		4
#define EXEIN_PROT_SCHEMAREQUEST	5
#define EXEIN_NN_MAX_SIZE		50

typedef struct {
        u32 key;
        u8  message_id;
        u8  padding;
        u16 tag;
        pid_t pid;
} exein_prot_req_t;

typedef struct {
	u16 tag;
	u64 timestamp;
	pid_t pid;
	int processing;
	u16 seqn;
	struct hlist_node next;
} exein_reg_data;

int exein_delete_expired_regs(void);
