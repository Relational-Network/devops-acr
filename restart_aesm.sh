# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2022 Gramine Project

set -e

killall -q aesm_service || true

AESM_PATH=/opt/intel/sgx-aesm-service/aesm LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm exec /opt/intel/sgx-aesm-service/aesm/aesm_service --no-syslog