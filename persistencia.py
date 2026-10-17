"""Leitura e gravação de arrays de objetos JSON em disco."""

import json
import os
from datetime import datetime


class ErroPersistencia(Exception):
    """Falha ao ler ou gravar a base de dados."""


class RepositorioJSON:
    """Guarda uma lista de dicionários como um array JSON em um arquivo."""

    def __init__(self, caminho: str):
        self.caminho = caminho
        pasta = os.path.dirname(caminho)
        if pasta:
            os.makedirs(pasta, exist_ok=True)

    def carregar(self) -> list[dict]:
        """Lê o array JSON. Arquivo inexistente ou vazio = base vazia.

        Se o arquivo estiver corrompido, ele é renomeado para backup em vez de
        ser sobrescrito no próximo salvamento (evita perder todos os dados).
        """
        if not os.path.exists(self.caminho):
            return []
        try:
            with open(self.caminho, "r", encoding="utf-8") as arquivo:
                conteudo = arquivo.read().strip()
            if not conteudo:
                return []
            dados = json.loads(conteudo)
            if not isinstance(dados, list):
                raise ValueError("o arquivo não contém um array JSON")
            return dados
        except (json.JSONDecodeError, ValueError) as erro:
            backup = self._mover_para_backup()
            raise ErroPersistencia(
                f"Arquivo '{self.caminho}' inválido ({erro}). "
                f"Cópia preservada em '{backup}'; iniciando base vazia."
            ) from erro
        except OSError as erro:
            raise ErroPersistencia(f"Não foi possível ler '{self.caminho}': {erro}") from erro

    def salvar(self, dados: list[dict]) -> None:
        """Gravação atômica: escreve num arquivo temporário e troca de uma vez.

        Se o programa cair no meio da escrita, o arquivo original continua intacto.
        """
        temporario = self.caminho + ".tmp"
        try:
            with open(temporario, "w", encoding="utf-8") as arquivo:
                json.dump(dados, arquivo, indent=4, ensure_ascii=False)
            os.replace(temporario, self.caminho)
        except OSError as erro:
            raise ErroPersistencia(f"Não foi possível gravar '{self.caminho}': {erro}") from erro

    def _mover_para_backup(self) -> str:
        carimbo = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = f"{self.caminho}.corrompido-{carimbo}"
        try:
            os.replace(self.caminho, backup)
        except OSError:
            return "(falha ao criar backup)"
        return backup
