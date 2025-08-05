#!/usr/bin/env python3
"""
Módulo Logger de Segurança
Sistema de logging discreto para ferramentas ofensivas
"""

import logging
import sys
from datetime import datetime
from pathlib import Path

class SecurityLogger:
    """Logger especializado para ferramentas de segurança"""
    
    def __init__(self, verbose=False, log_file=None):
        self.verbose = verbose
        self.log_file = log_file
        
        # Configurar cores para output
        self.colors = {
            'INFO': '\033[94m',      # Azul
            'SUCCESS': '\033[92m',   # Verde
            'WARNING': '\033[93m',   # Amarelo
            'ERROR': '\033[91m',     # Vermelho
            'DEBUG': '\033[95m',     # Magenta
            'RESET': '\033[0m'       # Reset
        }
        
        # Configurar logger interno se necessário
        if log_file:
            self._setup_file_logger()
    
    def _setup_file_logger(self):
        """Configura logging para arquivo"""
        if not self.log_file:
            return
            
        self.file_logger = logging.getLogger('SecurityLogger')
        self.file_logger.setLevel(logging.DEBUG)
        
        # Handler para arquivo
        handler = logging.FileHandler(str(self.log_file))
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.file_logger.addHandler(handler)
    
    def _log(self, level, message, color=None):
        """Método interno de logging"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Formato da mensagem
        if color and sys.stdout.isatty():
            formatted_msg = f"{color}[{timestamp}] {level}: {message}{self.colors['RESET']}"
        else:
            formatted_msg = f"[{timestamp}] {level}: {message}"
        
        # Imprimir na tela
        print(formatted_msg)
        
        # Salvar em arquivo se configurado
        if hasattr(self, 'file_logger'):
            self.file_logger.log(getattr(logging, level), message)
    
    def info(self, message):
        """Log de informação"""
        self._log("INFO", message, self.colors['INFO'])
    
    def success(self, message):
        """Log de sucesso"""
        self._log("SUCCESS", message, self.colors['SUCCESS'])
    
    def warning(self, message):
        """Log de aviso"""
        self._log("WARNING", message, self.colors['WARNING'])
    
    def error(self, message):
        """Log de erro"""
        self._log("ERROR", message, self.colors['ERROR'])
    
    def debug(self, message):
        """Log de debug (apenas se verbose=True)"""
        if self.verbose:
            self._log("DEBUG", message, self.colors['DEBUG'])
    
    def critical(self, message):
        """Log crítico"""
        self._log("CRITICAL", message, self.colors['ERROR'])
    
    def stealth(self, message):
        """Log stealth - apenas para arquivo, sem output na tela"""
        if hasattr(self, 'file_logger'):
            self.file_logger.info(f"[STEALTH] {message}") 