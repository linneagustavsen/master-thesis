#!/bin/bash
interface=$(routel 2>/dev/null | grep default | awk '{ print $3 }' | head -1)

