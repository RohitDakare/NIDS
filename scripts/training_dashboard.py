#!/usr/bin/env python3
"""
ML Training Dashboard for NIDS

A web-based dashboard to monitor and manage ML model training.
Provides real-time training progress, model comparison, and deployment management.
"""

import os
import sys
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel

from ml_training_pipeline import NIDSTrainingPipeline

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(title="NIDS ML Training Dashboard", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
training_status = {
    "is_training": False,
    "current_step": "",
    "progress": 0,
    "start_time": None,
    "logs": [],
    "error": None
}

training_history = []
current_pipeline = None

# Pydantic models
class TrainingConfig(BaseModel):
    data_path: str = "data/cic-ids2017"
    test_size: float = 0.2
    random_state: int = 42
    cv_folds: int = 5
    models: Dict[str, Dict] = {
        "random_forest": {"enabled": True},
        "gradient_boosting": {"enabled": True},
        "isolation_forest": {"enabled": True},
        "one_class_svm": {"enabled": False}
    }
    use_smote: bool = True
    save_plots: bool = True
    auto_deploy: bool = True

class TrainingRequest(BaseModel):
    config: TrainingConfig

# API Routes
@app.get("/")
async def dashboard():
    """Serve the training dashboard"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>NIDS ML Training Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body class="bg-gray-100">
        <div class="container mx-auto px-4 py-8" x-data="trainingDashboard()">
            <div class="bg-white rounded-lg shadow-lg p-6 mb-6">
                <h1 class="text-3xl font-bold text-gray-800 mb-2">NIDS ML Training Dashboard</h1>
                <p class="text-gray-600">Monitor and manage machine learning model training</p>
            </div>

            <!-- Training Status -->
            <div class="bg-white rounded-lg shadow-lg p-6 mb-6">
                <h2 class="text-xl font-semibold mb-4">Training Status</h2>
                
                <div x-show="!status.is_training" class="text-center py-8">
                    <div class="text-gray-500 mb-4">
                        <svg class="w-16 h-16 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a9 9 0 117.072 0l-.548.547A3.374 3.374 0 0014.846 21H9.154a3.374 3.374 0 00-2.53-1.103l-.548-.547z"></path>
                        </svg>
                    </div>
                    <h3 class="text-lg font-medium text-gray-800 mb-2">Ready to Train</h3>
                    <p class="text-gray-600 mb-4">Configure your training parameters and start training</p>
                    <button @click="startTraining()" 
                            class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-lg font-medium">
                        Start Training
                    </button>
                </div>

                <div x-show="status.is_training" class="space-y-4">
                    <div class="flex items-center justify-between">
                        <h3 class="text-lg font-medium text-gray-800">Training in Progress</h3>
                        <button @click="stopTraining()" 
                                class="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded font-medium">
                            Stop Training
                        </button>
                    </div>
                    
                    <div class="bg-gray-200 rounded-full h-4">
                        <div class="bg-blue-500 h-4 rounded-full transition-all duration-300" 
                             :style="`width: ${status.progress}%`"></div>
                    </div>
                    
                    <div class="text-sm text-gray-600">
                        <p><strong>Current Step:</strong> <span x-text="status.current_step"></span></p>
                        <p><strong>Progress:</strong> <span x-text="status.progress"></span>%</p>
                        <p x-show="status.start_time"><strong>Started:</strong> <span x-text="formatTime(status.start_time)"></span></p>
                    </div>
                </div>

                <div x-show="status.error" class="mt-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">
                    <h4 class="font-medium">Training Error:</h4>
                    <p x-text="status.error"></p>
                </div>
            </div>

            <!-- Training Configuration -->
            <div class="bg-white rounded-lg shadow-lg p-6 mb-6">
                <h2 class="text-xl font-semibold mb-4">Training Configuration</h2>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Data Path</label>
                        <input type="text" x-model="config.data_path" 
                               class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Test Size</label>
                        <input type="number" x-model="config.test_size" step="0.1" min="0.1" max="0.5"
                               class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Random State</label>
                        <input type="number" x-model="config.random_state" 
                               class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">CV Folds</label>
                        <input type="number" x-model="config.cv_folds" min="3" max="10"
                               class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                </div>

                <div class="mt-6">
                    <h3 class="text-lg font-medium text-gray-800 mb-3">Models to Train</h3>
                    <div class="grid grid-cols-2 gap-4">
                        <template x-for="(modelConfig, modelName) in config.models" :key="modelName">
                            <label class="flex items-center space-x-2">
                                <input type="checkbox" x-model="modelConfig.enabled" class="rounded">
                                <span class="text-sm font-medium" x-text="modelName.replace('_', ' ').toUpperCase()"></span>
                            </label>
                        </template>
                    </div>
                </div>

                <div class="mt-6 flex space-x-4">
                    <label class="flex items-center space-x-2">
                        <input type="checkbox" x-model="config.use_smote" class="rounded">
                        <span class="text-sm font-medium">Use SMOTE</span>
                    </label>
                    <label class="flex items-center space-x-2">
                        <input type="checkbox" x-model="config.save_plots" class="rounded">
                        <span class="text-sm font-medium">Save Plots</span>
                    </label>
                    <label class="flex items-center space-x-2">
                        <input type="checkbox" x-model="config.auto_deploy" class="rounded">
                        <span class="text-sm font-medium">Auto Deploy</span>
                    </label>
                </div>
            </div>

            <!-- Training History -->
            <div class="bg-white rounded-lg shadow-lg p-6 mb-6">
                <h2 class="text-xl font-semibold mb-4">Training History</h2>
                
                <div x-show="history.length === 0" class="text-center py-8 text-gray-500">
                    No training history available
                </div>

                <div x-show="history.length > 0" class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Best Model</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Accuracy</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <template x-for="run in history" :key="run.id">
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900" x-text="formatTime(run.timestamp)"></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900" x-text="run.best_model"></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900" x-text="(run.accuracy * 100).toFixed(2) + '%'"></td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                                            Completed
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                        <button @click="viewReport(run.id)" class="text-blue-600 hover:text-blue-900">View Report</button>
                                    </td>
                                </tr>
                            </template>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Training Logs -->
            <div class="bg-white rounded-lg shadow-lg p-6">
                <h2 class="text-xl font-semibold mb-4">Training Logs</h2>
                
                <div class="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm max-h-96 overflow-y-auto">
                    <div x-show="status.logs.length === 0" class="text-gray-500">No logs available</div>
                    <template x-for="log in status.logs" :key="log.timestamp">
                        <div class="mb-1">
                            <span class="text-gray-400" x-text="formatTime(log.timestamp)"></span>
                            <span x-text="log.message"></span>
                        </div>
                    </template>
                </div>
            </div>
        </div>

        <script>
            function trainingDashboard() {
                return {
                    status: {
                        is_training: false,
                        current_step: '',
                        progress: 0,
                        start_time: null,
                        logs: [],
                        error: null
                    },
                    config: {
                        data_path: 'data/cic-ids2017',
                        test_size: 0.2,
                        random_state: 42,
                        cv_folds: 5,
                        models: {
                            random_forest: { enabled: true },
                            gradient_boosting: { enabled: true },
                            isolation_forest: { enabled: true },
                            one_class_svm: { enabled: false }
                        },
                        use_smote: true,
                        save_plots: true,
                        auto_deploy: true
                    },
                    history: [],

                    init() {
                        this.loadStatus();
                        this.loadHistory();
                        setInterval(() => this.loadStatus(), 2000);
                    },

                    async loadStatus() {
                        try {
                            const response = await fetch('/api/status');
                            this.status = await response.json();
                        } catch (error) {
                            console.error('Failed to load status:', error);
                        }
                    },

                    async loadHistory() {
                        try {
                            const response = await fetch('/api/history');
                            this.history = await response.json();
                        } catch (error) {
                            console.error('Failed to load history:', error);
                        }
                    },

                    async startTraining() {
                        try {
                            const response = await fetch('/api/train', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ config: this.config })
                            });
                            
                            if (!response.ok) {
                                throw new Error('Failed to start training');
                            }
                            
                            this.loadStatus();
                        } catch (error) {
                            alert('Failed to start training: ' + error.message);
                        }
                    },

                    async stopTraining() {
                        try {
                            const response = await fetch('/api/stop', { method: 'POST' });
                            if (!response.ok) {
                                throw new Error('Failed to stop training');
                            }
                            this.loadStatus();
                        } catch (error) {
                            alert('Failed to stop training: ' + error.message);
                        }
                    },

                    formatTime(timestamp) {
                        if (!timestamp) return '';
                        return new Date(timestamp).toLocaleString();
                    },

                    viewReport(runId) {
                        window.open(`/api/report/${runId}`, '_blank');
                    }
                }
            }
        </script>
    </body>
    </html>
    """)

@app.get("/api/status")
async def get_status():
    """Get current training status"""
    return training_status

@app.get("/api/history")
async def get_history():
    """Get training history"""
    return training_history

@app.post("/api/train")
async def start_training(request: TrainingRequest, background_tasks: BackgroundTasks):
    """Start model training"""
    global training_status, current_pipeline
    
    if training_status["is_training"]:
        raise HTTPException(status_code=400, detail="Training already in progress")
    
    # Reset status
    training_status.update({
        "is_training": True,
        "current_step": "Initializing...",
        "progress": 0,
        "start_time": datetime.now().isoformat(),
        "logs": [],
        "error": None
    })
    
    # Start training in background
    background_tasks.add_task(run_training, request.config.dict())
    
    return {"message": "Training started"}

@app.post("/api/stop")
async def stop_training():
    """Stop current training"""
    global training_status, current_pipeline
    
    if not training_status["is_training"]:
        raise HTTPException(status_code=400, detail="No training in progress")
    
    training_status["is_training"] = False
    training_status["current_step"] = "Stopped"
    
    return {"message": "Training stopped"}

@app.get("/api/report/{run_id}")
async def get_report(run_id: str):
    """Get training report"""
    report_path = Path("training_results") / f"training_report_{run_id}.json"
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(report_path)

async def run_training(config: Dict[str, Any]):
    """Run training pipeline in background"""
    global training_status, training_history, current_pipeline
    
    try:
        # Create pipeline
        current_pipeline = NIDSTrainingPipeline(config)
        
        # Custom logger to capture progress
        class ProgressHandler(logging.Handler):
            def emit(self, record):
                message = self.format(record)
                training_status["logs"].append({
                    "timestamp": datetime.now().isoformat(),
                    "message": message
                })
                
                # Update progress based on log messages
                if "Loading" in message:
                    training_status["progress"] = 10
                    training_status["current_step"] = "Loading data"
                elif "Preprocessing" in message:
                    training_status["progress"] = 20
                    training_status["current_step"] = "Preprocessing data"
                elif "Training" in message:
                    training_status["progress"] = 40
                    training_status["current_step"] = "Training models"
                elif "Evaluating" in message:
                    training_status["progress"] = 70
                    training_status["current_step"] = "Evaluating models"
                elif "Saving" in message:
                    training_status["progress"] = 90
                    training_status["current_step"] = "Saving results"
                elif "completed successfully" in message:
                    training_status["progress"] = 100
                    training_status["current_step"] = "Completed"
        
        # Add progress handler
        progress_handler = ProgressHandler()
        current_pipeline.logger.addHandler(progress_handler)
        
        # Run training
        success = current_pipeline.run_pipeline()
        
        if success:
            # Add to history
            run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            training_history.append({
                "id": run_id,
                "timestamp": datetime.now().isoformat(),
                "best_model": "random_forest",  # This would come from results
                "accuracy": 0.95,  # This would come from results
                "status": "completed"
            })
            
            training_status["is_training"] = False
            training_status["current_step"] = "Completed successfully"
        else:
            training_status["error"] = "Training failed"
            training_status["is_training"] = False
            
    except Exception as e:
        logger.error(f"Training failed: {e}")
        training_status["error"] = str(e)
        training_status["is_training"] = False

def main():
    """Run the training dashboard"""
    print("🚀 Starting NIDS ML Training Dashboard...")
    print("📊 Dashboard will be available at: http://localhost:8001")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        log_level="info"
    )

if __name__ == "__main__":
    main()
