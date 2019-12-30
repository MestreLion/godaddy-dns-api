#!/bin/bash -ue
#
# renew.sh - Helper to renew WAN lease
#
#    Copyright (C) 2019 Rodrigo Silva (MestreLion) <linux@rodrigosilva.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. See <http://www.gnu.org/licenses/gpl.html>

config=${XDG_CONFIG_HOME:-$HOME/.config}/godaddy-dns-api.conf
source "$config"

lease=${1:-1}  # 0=No Change, 1=Renew, 2=Release
csrf=$(curl -s "${RENEW_HOST}${RENEW_CSRF}" -H "Authorization: Basic ${RENEW_AUTH}" |
	grep CSRFValue | grep -o '[0-9]*')

data='WanConnectionType=0&MtuSize=0&SpoofedMacAddressMA0=00&SpoofedMacAddressMA1=00&SpoofedMacAddressMA2=00&SpoofedMacAddressMA3=00&SpoofedMacAddressMA4=00&SpoofedMacAddressMA5=00'

curl "${RENEW_HOST}${RENEW_PATH}" -H "Authorization: Basic ${RENEW_AUTH}" --data "CSRFValue=${csrf}&WanLeaseAction=${lease}&${data}"
