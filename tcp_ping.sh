#!/bin/bash
curl --interface tun0 -d '{"key1":"value1","key2":"value2"}' -H "Content-Type: application/json" http://192.168.0.2