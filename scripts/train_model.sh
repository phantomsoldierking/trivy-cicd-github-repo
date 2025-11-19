#!/bin/bash

set -e

echo "======================================================================"
echo "  Training ML Models"
echo "======================================================================"

docker-compose exec ml_service python train_model.py

echo "======================================================================"
echo "  Training Complete!"
echo "  View models at: http://localhost:5000"
echo "======================================================================"
