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

#include "exein_nn_main.h"
#include <linux/string.h> 
#include "exein_lsm.h"

int playnn(exein_feature_t *NNInput)
{
	exein_delete_expired_regs();
	return 0;
}
