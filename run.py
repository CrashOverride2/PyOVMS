# PyOVMS — a Python server for the Open Vehicle Monitoring System (OVMS) protocols.
# Copyright (C) 2026 Carsten Schmiemann
#
# This program is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License, version 3, as published by the Free Software
# Foundation. This program is licensed under version 3 only — the "or (at your option)
# any later version" clause is deliberately NOT granted.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this
# program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-only

# Ensure .env exists and all critical secrets are customised before anything
# from app.config is imported (Settings() reads .env at class instantiation).
from app.secret_initializer import ensure_secrets
ensure_secrets()

# Now, import the rest of the application server components.
import uvicorn
from app.config import settings

if __name__ == "__main__":

    uvicorn.run(
        "app.main:app",
        host=settings.SERVER_HOST,
        port=settings.HTTP_PORT,
        reload=False,
        log_config=None,
        proxy_headers=True,
        forwarded_allow_ips=settings.FORWARDED_ALLOW_IPS,
        server_header=False,
        workers=1
    )