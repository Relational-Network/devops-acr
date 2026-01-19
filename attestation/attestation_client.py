# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# attestation/attestation_client.py
import os
import subprocess
import logging
import tempfile
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

class AttestationClient:
    """Client for remote attestation of TEE instances"""
    
    def __init__(self, attest_binary_path: str = "/usr/local/bin/attest"):
        """
        Initialize the attestation client
        
        Args:
            attest_binary_path: Path to the attest binary
        """
        self.attest_binary_path = attest_binary_path
        if not os.path.exists(self.attest_binary_path):
            logger.warning(f"Attest binary not found at {self.attest_binary_path}")
            
    def verify_attestation(
        self, 
        host: str, 
        port: int, 
        mrenclave: str, 
        mrsigner: str, 
        isvprodid: str = "0", 
        isvsvn: str = "0",
        timeout: int = 60,
        max_retries: int = 3,
        retry_delay: int = 5
    ) -> Tuple[bool, Optional[Dict]]:
        """
        Verify attestation for a remote TEE instance
        
        Args:
            host: The hostname or IP address of the TEE instance
            port: The port to connect to
            mrenclave: The MRENCLAVE measurement (hex)
            mrsigner: The MRSIGNER measurement (hex)
            isvprodid: The ISV product ID (default: 0)
            isvsvn: The ISV SVN (default: 0)
            timeout: Timeout in seconds for the attestation process
            max_retries: Maximum number of retries on failure
            retry_delay: Delay between retries in seconds
            
        Returns:
            Tuple of (success, details)
            success: Boolean indicating if attestation was successful
            details: Dictionary with details or error message
        """
        if not os.path.exists(self.attest_binary_path):
            return False, {"error": f"Attest binary not found at {self.attest_binary_path}"}
        
        # Set environment variables for the attestation
        env = os.environ.copy()
        env["APPLICATION_HOST"] = host
        env["APPLICATION_PORT"] = str(port)
        
        # Prepare the command
        cmd = [
            self.attest_binary_path,
            "dcap",
            mrenclave,
            mrsigner,
            isvprodid,
            isvsvn
        ]
        
        logger.info(f"Running attestation for {host}:{port} with measurements: {mrenclave}, {mrsigner}")
        
        attempt = 0
        while attempt < max_retries:
            attempt += 1
            
            try:
                with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                    # Run the attestation command
                    start_time = time.time()
                    process = subprocess.Popen(
                        cmd, 
                        env=env,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        text=True
                    )
                    
                    # Wait for the process to complete with timeout
                    try:
                        process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        logger.error(f"Attestation timed out after {timeout} seconds")
                        return False, {"error": f"Attestation timed out after {timeout} seconds"}
                    
                    # Get stdout and stderr
                    stdout_file.seek(0)
                    stderr_file.seek(0)
                    stdout = stdout_file.read().decode('utf-8')
                    stderr = stderr_file.read().decode('utf-8')
                    
                    duration = time.time() - start_time
                    
                    # Check if attestation was successful
                    if process.returncode == 0:
                        logger.info(f"Attestation successful for {host}:{port} (completed in {duration:.2f}s)")
                        return True, {
                            "success": True,
                            "host": host,
                            "port": port,
                            "mrenclave": mrenclave,
                            "mrsigner": mrsigner,
                            "stdout": stdout,
                            "duration_seconds": duration
                        }
                    else:
                        logger.warning(f"Attestation failed for {host}:{port} with exit code {process.returncode} (attempt {attempt}/{max_retries})")
                        
                        if attempt >= max_retries:
                            return False, {
                                "success": False,
                                "error": f"Attestation failed with exit code {process.returncode}",
                                "stdout": stdout,
                                "stderr": stderr
                            }
                        
                        logger.info(f"Retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        
            except Exception as e:
                logger.error(f"Error running attestation: {str(e)}")
                if attempt >= max_retries:
                    return False, {"error": f"Error running attestation: {str(e)}"}
                
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                
        # This should not be reached, but just in case
        return False, {"error": "Attestation failed after all retries"}