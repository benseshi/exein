/* Copyright 2020 Exein. All Rights Reserved.

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


#define BUFFER128
#include "../include/libexnl.h"

uint16_t pidl4=0;
uint16_t data[EXEIN_BUFFES_SIZE];

volatile int run = 1;

void test_cb(uint16_t pid){
//	if (pidl4==0)
pidl4=pid;
	printf("testexnl - Now checking pid %d\n", pid);
}
void handle_signal(int signum, siginfo_t *si, void *ct)
{
  run = 0;
}


int main(int argc, char *argv[]){
	exein_shandle	*h;
	int 		i=0;
	int		count=0;

	if (argc!=3) {
		printf("testexnl - wrong arguments count\nusage:%s <key> <tag>\n", argv[0]);
		exit(-1);
		}

  if (exein_register_callback_signal(SIGINT, &handle_signal) < 0) return 1;

  if (exein_register_callback_signal(SIGTERM, &handle_signal) < 0) return 1;

	printf("testexnl - Print version\n");
	exein_print_version();
	printf("testexnl - Registering call backs\n");
	exein_new_pid_notify_cb=&test_cb;
	exein_delete_pid_cb=&exein_dummy_pid_delete_cb;
	printf("testexnl - start agent\n");
	h=exein_agent_start(atoi(argv[1]),atoi(argv[2]));
	if (h) while (run){
		if (pidl4!=0) {
			printf("testexnl - Fetch data pid=%d\n", pidl4);
			if (exein_fetch_data(h, pidl4, data)==EXEIN_NOERR){
				printf("testexnl - Data (%d, %d) ==> [", pidl4, count);
				for (i=0;i<EXEIN_BUFFES_SIZE;i++){
					printf("%d, ",data[i]);
					}
				printf("]\n");
				}
			}
#if 0
		sleep(5);
		count++;
		if (count==10){
			printf("testexnl - stop Agent\n");
			exein_agent_stop(h);
			exit(1);
			}
#endif
		}

  printf("testexnl - stop Agent\n");
  exein_agent_stop(h);
  return 0;	
}
