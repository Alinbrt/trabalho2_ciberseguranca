"""Modelo linear de análise de risco (Requisito 4 da 2ª atividade).

    M  (n x m)  matriz de incidência: M[i][j] = 1 se a vulnerabilidade j está
                ATIVA (não corrigida) no equipamento i
    v  (m)      vetor de severidade (nota CVSS de cada vulnerabilidade)
    W  (n x n)  matriz diagonal de exposição: W[i][i] = 1 + fator_exposicao(i)
    b  (n)      risco próprio: b = W M v
    A  (n x n)  matriz de dependências: A[i][j] = fração do risco de j herdada por i
    x  (n)      risco efetivo: x = b + A x  <=>  (I - A) x = b
"""

from dataclasses import dataclass

import numpy as np

from enums import StatusTratamento
from modelos import Dependencia, Equipamento


@dataclass
class Diagnostico:
    """Resultado da verificação de invertibilidade de I - A."""

    invertivel: bool
    diagonal_dominante: bool
    determinante: float
    numero_condicao: float
    mensagem: str


@dataclass
class ResultadoRisco:
    """Risco de um equipamento. risco_efetivo é None se o sistema não tiver solução."""

    equipamento: Equipamento
    risco_proprio: float
    risco_efetivo: float | None


class ModeloAnaliseRisco:
    """Monta M, v, W e A a partir do inventário e resolve (I - A) x = b."""

    # Acima disso a solução perde dígitos demais para ser confiável
    # (erro relativo em x pode chegar a cond * erro relativo em b).
    LIMITE_CONDICAO = 1e12

    def __init__(self, equipamentos: list[Equipamento], dependencias: list[Dependencia]):
        self.equipamentos = equipamentos
        self.n = len(equipamentos)
        # Linha i da matriz <-> equipamento (dicionário id -> índice)
        self.indice_equipamento = {eq.id_ativo: i for i, eq in enumerate(equipamentos)}
        self._indexar_vulnerabilidades()
        self.A = self._montar_matriz_dependencias(dependencias)

    # ------------------------------------------------------------------
    # Montagem das estruturas
    # ------------------------------------------------------------------
    def _indexar_vulnerabilidades(self) -> None:
        """Mapeia cada CVE único para uma coluna j (dicionário CVE -> índice)."""
        self.indice_vulnerabilidade: dict[str, int] = {}
        self.cvss_por_coluna: list[float] = []
        for eq in self.equipamentos:
            for vuln in eq.vulnerabilidades:
                if vuln.cve not in self.indice_vulnerabilidade:
                    self.indice_vulnerabilidade[vuln.cve] = len(self.cvss_por_coluna)
                    self.cvss_por_coluna.append(vuln.cvss)
        self.m = len(self.cvss_por_coluna)

    def _montar_matriz_dependencias(self, dependencias: list[Dependencia]) -> np.ndarray:
        A = np.zeros((self.n, self.n))
        for dep in dependencias:
            i = self.indice_equipamento.get(dep.id_destino)
            j = self.indice_equipamento.get(dep.id_origem)
            if i is not None and j is not None:  # ignora ativos inexistentes
                A[i, j] = dep.fracao
        return A

    def matriz_incidencia(self) -> np.ndarray:
        """M representa a exposição ATIVA: vulnerabilidade corrigida não incide no ativo.

        O status fica em M (e não em v) porque ele pertence ao par
        (equipamento, vulnerabilidade): o mesmo CVE pode estar corrigido em um
        ativo e aberto em outro.
        """
        M = np.zeros((self.n, self.m))
        for i, eq in enumerate(self.equipamentos):
            for vuln in eq.vulnerabilidades:
                if vuln.status != StatusTratamento.CORRIGIDA:
                    M[i, self.indice_vulnerabilidade[vuln.cve]] = 1.0
        return M

    def vetor_severidade(self) -> np.ndarray:
        return np.array(self.cvss_por_coluna, dtype=float)

    def matriz_exposicao(self) -> np.ndarray:
        """W = diag(1 + fator_exposicao): o polimorfismo entra no modelo aqui."""
        return np.diag([1.0 + eq.fator_exposicao() for eq in self.equipamentos])

    # ------------------------------------------------------------------
    # Cálculos
    # ------------------------------------------------------------------
    def calcular_risco_proprio(self) -> np.ndarray:
        """b = W M v. M leva o espaço das vulnerabilidades ao dos equipamentos."""
        return self.matriz_exposicao() @ self.matriz_incidencia() @ self.vetor_severidade()

    def eh_diagonal_dominante(self) -> bool:
        """I - A é estritamente diagonal dominante se, em cada linha,
        |1 - A_ii| > soma |A_ij| (j != i). Como A_ii = 0: soma da linha de A < 1."""
        diagonal = np.abs(np.diag(np.eye(self.n) - self.A))
        fora_diagonal = np.sum(np.abs(self.A), axis=1) - np.abs(np.diag(self.A))
        return bool(np.all(diagonal > fora_diagonal))

    def verificar_invertibilidade(self) -> Diagnostico:
        """Verifica se (I - A) x = b tem solução única e confiável.

        - Dominância diagonal estrita GARANTE a invertibilidade (condição suficiente).
        - Sem ela, o número de condição decide: se for infinito ou enorme, a
          matriz é singular ou tão próxima disso que a solução não é confiável.
        - O determinante é exibido só como informação: seu valor muda com a
          escala da matriz, então não serve como critério isolado.
        """
        if self.n == 0:
            return Diagnostico(False, False, 0.0, float("inf"), "Nenhum equipamento cadastrado.")

        sistema = np.eye(self.n) - self.A
        determinante = float(np.linalg.det(sistema))
        condicao = float(np.linalg.cond(sistema))
        dominante = self.eh_diagonal_dominante()

        if dominante:
            mensagem = "Sistema invertível: I - A é estritamente diagonal dominante."
            invertivel = True
        elif np.isfinite(condicao) and condicao < self.LIMITE_CONDICAO:
            mensagem = "Sistema invertível (sem dominância diagonal, mas bem condicionado)."
            invertivel = True
        else:
            mensagem = (
                "Sistema singular ou mal condicionado: o risco efetivo não pode ser "
                "calculado. Revise as dependências (soma de cada linha deve ser < 1)."
            )
            invertivel = False

        return Diagnostico(invertivel, dominante, determinante, condicao, mensagem)

    def calcular(self) -> tuple[list[ResultadoRisco], Diagnostico]:
        """Calcula o risco próprio e, se possível, o risco efetivo de cada equipamento."""
        b = self.calcular_risco_proprio()
        diagnostico = self.verificar_invertibilidade()

        x = None
        if diagnostico.invertivel:
            try:
                # Resolver direto (fatoração LU) é mais preciso e barato que inv(I - A) @ b
                x = np.linalg.solve(np.eye(self.n) - self.A, b)
            except np.linalg.LinAlgError as erro:
                diagnostico.invertivel = False
                diagnostico.mensagem = f"Falha numérica ao resolver o sistema: {erro}"

        resultados = [
            ResultadoRisco(eq, float(b[i]), None if x is None else float(x[i]))
            for i, eq in enumerate(self.equipamentos)
        ]
        return resultados, diagnostico