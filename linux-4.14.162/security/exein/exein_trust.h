/*
 * exein Linux Security Module
 *
 * Authors: Alessandro Carminati <alessandro@exein.io>,
 *          Gianluigi Spagnuolo <gianluigi@exein.io>,
 *          Alan Vivona <alan@exein.io>
 *
 * Copyright (C) 2020 Exein, SpA.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/list.h>

#include "exein_types.h"
#include "exein_print_level.h"

void exein_mark_not_trusted(uint16_t tag, pid_t pid);
