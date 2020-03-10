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

#include <stdio.h>
#include "../config.h"
#include <stdlib.h>


int main(int argc, char **argv)
{
	char keynum=0, secnum=3;
	sections_t section_head = {0};
	int tmp;

	if (!((argc!=3)||(argc!=5))) {
		printf("call:\n\tinibuilder file.ini section_name [key_name key_value]\n");
		exit(1);
		}

	read_ini_file(argv[1], &section_head);
        if (argc==3){
		if (tmp=add_section(argv[2], &section_head)){
			printf("section ADD FAIL! (%d)\n", tmp);
			return 1;
			}
		} else {
		if (tmp=add_key(argv[2],argv[3],argv[4], &section_head)){
			printf("Key ADD FAIL! in [%s] <- %s=%s - %d\n",argv[2],argv[3],argv[4], tmp);
			return 1;
			}
		}
	print_ini(&section_head);
	return 0;
}
