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


#include <unistd.h>
#include <signal.h>

#include <sys/types.h>

int exein_register_callback_signal(int signum, void (*call)(int signum, siginfo_t *si, void *ct))
{
  struct sigaction sa = {
    .sa_sigaction = call,
    .sa_flags     = SA_SIGINFO,
    .sa_restorer  = NULL
  };

  sigemptyset(&(sa.sa_mask));

  return sigaction(signum, &sa, NULL);
}
