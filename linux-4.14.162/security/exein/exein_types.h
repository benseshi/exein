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
#include <linux/types.h>
#include <linux/list.h>

#ifndef EXEIN_TYPES_INCLUDED
#define EXEIN_TYPES_INCLUDED

#define NNINPUT_SIZE 2
typedef u16 exein_feature_t;


// define struct
typedef struct {
    uint16_t tag;
    pid_t pid;
    int val;
    struct list_head list;
} exein_trust_t;

#endif
