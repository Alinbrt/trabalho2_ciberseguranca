"""Enumerações do domínio: tipos de ativo, severidade e status de tratamento."""

from enum import Enum


class TipoAtivo(Enum):
    """Tipos de ativo de TI. Cada tipo tem um código inteiro de referência."""

    NOTEBOOK = 1
    SERVIDOR = 2
    ROTEADOR = 3
    ESTACAO_TRABALHO = 4
    APLICACAO_WEB = 5
    BANCO_DE_DADOS = 6

    @property
    def rotulo(self) -> str:
        """Nome legível para exibição (ex.: 'Estacao trabalho')."""
        return self.name.replace("_", " ").capitalize()


class Severidade(Enum):
    """Escala de severidade, alinhada às faixas oficiais do CVSS v3."""

    BAIXA = "Baixa"
    MEDIA = "Média"
    ALTA = "Alta"
    CRITICA = "Crítica"

    @property
    def rotulo(self) -> str:
        return self.value

    @property
    def faixa_cvss(self) -> tuple[float, float]:
        """Intervalo fechado de notas CVSS v3 correspondente à severidade."""
        return _FAIXAS_CVSS[self]

    @property
    def cvss_padrao(self) -> float:
        """Nota usada quando o usuário não informa o CVSS: ponto médio da faixa."""
        minimo, maximo = self.faixa_cvss
        return round((minimo + maximo) / 2, 1)


# Faixas oficiais do CVSS v3. Ficam fora da classe porque membros de Enum
# não podem guardar atributos de classe comuns.
_FAIXAS_CVSS = {
    Severidade.BAIXA: (0.1, 3.9),
    Severidade.MEDIA: (4.0, 6.9),
    Severidade.ALTA: (7.0, 8.9),
    Severidade.CRITICA: (9.0, 10.0),
}


class StatusTratamento(Enum):
    """Situação de tratamento de uma vulnerabilidade em um ativo."""

    ABERTA = "Aberta"
    EM_TRATAMENTO = "Em Tratamento"
    CORRIGIDA = "Corrigida"
    ACEITA = "Aceita como Risco"

    @property
    def rotulo(self) -> str:
        return self.value