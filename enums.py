from enum import Enum

class TipoEquipamento(Enum):
    NOTEBOOK = 1
    SERVIDOR = 2
    ROTEADOR = 3
    ESTACAO_TRABALLHO = 4

class NivelCriticidade(Enum):
    BAIXA = "Baixa"
    MEDIA = "Média"
    ALTA = "Alta"
    CRITICA = "Crítica"

class StatusVulnerabilidade(Enum):
    ABERTA = "Aberta"
    EM_TRATAMENTO = "Em Tratamento"
    CORRIGIDA = "Corrigida"
    ACEITA = "Aceita como risco"