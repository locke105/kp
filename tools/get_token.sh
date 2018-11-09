#!/bin/bash

export KP_IAM_TOKEN=$(bx iam oauth-tokens | awk '{ print $4 }')
