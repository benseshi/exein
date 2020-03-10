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

#include <linux/slab.h>
#include <linux/gfp.h>
#include "exein_types.h"
#include "exein_trust.h"
#include <linux/sched/signal.h>

void exein_mark_not_trusted(uint16_t tag, pid_t pid){
	int ret = kill_pid(find_vpid(pid), SIGKILL, 1);
	if (ret < 0) {
		printk(KERN_INFO "error kill pid\n");
		}
	printk(KERN_CRIT "EXEIN MARKED PROCESS AS NOT TRUSTED [tag:%d pid:%d]\n", tag, pid);
}
