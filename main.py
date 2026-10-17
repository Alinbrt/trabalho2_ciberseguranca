"""Ponto de entrada: menu textual do inventário de ativos de TI (evolução do Trabalho 1)."""

import os
import sys

import numpy as np

from analise_risco import ModeloAnaliseRisco
from enums import Severidade, StatusTratamento, TipoAtivo
from inventario import ErroInventario, Inventario
from modelos import Equipamento, Vulnerabilidade, criar_equipamento, validar_responsavel
from persistencia import ErroPersistencia


class Cancelado(Exception):
    """Usuário digitou 'c' para desistir da operação atual."""


class Entrada:
    """Leitura de dados do teclado com validação. Repete a pergunta até receber
    um valor válido; digitar 'c' cancela a operação atual."""

    @staticmethod
    def _ler(rotulo: str) -> str:
        valor = input(rotulo).strip()
        if valor.lower() == "c":
            raise Cancelado
        return valor

    @classmethod
    def texto(cls, rotulo: str, obrigatorio: bool = True, atual: str | None = None,
              validador=None) -> str | None:
        """Com 'atual', Enter vazio mantém o valor atual (retorna None).
        'validador' é uma função que lança ValueError se o valor for inválido."""
        sufixo = f" [{atual}]" if atual is not None else ""
        while True:
            valor = cls._ler(f"{rotulo}{sufixo}: ")
            if not valor:
                if atual is not None:
                    return None
                if not obrigatorio:
                    return ""
                print("  ! Campo obrigatório. Digite um valor (ou 'c' para cancelar).")
                continue
            if validador is not None:
                try:
                    validador(valor)
                except ValueError as erro:
                    print(f"  ! {erro}")
                    continue
            return valor

    @classmethod
    def inteiro(cls, rotulo: str, minimo: int | None = None, padrao: int | None = None) -> int:
        sufixo = f" [{padrao}]" if padrao is not None else ""
        while True:
            valor = cls._ler(f"{rotulo}{sufixo}: ")
            if not valor and padrao is not None:
                return padrao
            try:
                numero = int(valor)
            except ValueError:
                print("  ! Digite um número inteiro.")
                continue
            if minimo is not None and numero < minimo:
                print(f"  ! O valor deve ser no mínimo {minimo}.")
                continue
            return numero

    @classmethod
    def decimal(cls, rotulo: str, obrigatorio: bool = True) -> float | None:
        while True:
            valor = cls._ler(f"{rotulo}: ").replace(",", ".")
            if not valor and not obrigatorio:
                return None
            try:
                return float(valor)
            except ValueError:
                print("  ! Digite um número (ex.: 0.4 ou 7,5).")

    @classmethod
    def opcao_enum(cls, rotulo: str, enum_cls, permitir_manter: bool = False):
        """Lista os membros da enumeração e aceita o número OU o nome (como no Trabalho 1).
        Com permitir_manter, Enter vazio devolve None (manter o valor atual)."""
        membros = list(enum_cls)
        print(rotulo)
        for numero, membro in enumerate(membros, start=1):
            print(f"  {numero} - {membro.rotulo}")
        dica = "número ou nome" + (", Enter mantém" if permitir_manter else "")
        while True:
            valor = cls._ler(f"Escolha ({dica}): ")
            if not valor and permitir_manter:
                return None
            if valor.isdigit() and 1 <= int(valor) <= len(membros):
                return membros[int(valor) - 1]
            for membro in membros:
                if valor.lower() in (membro.rotulo.lower(), membro.name.lower()):
                    return membro
            print("  ! Opção inválida. Digite o número ou o nome de uma das opções.")

    @staticmethod
    def confirmar(pergunta: str) -> bool:
        while True:
            resposta = input(f"{pergunta} (s/n): ").strip().lower()
            if resposta in ("s", "sim"):
                return True
            if resposta in ("n", "nao", "não", "c"):
                return False
            print("  ! Responda 's' ou 'n'.")


class AplicacaoCLI:
    """Menu principal. Cada opção é um método, mapeado num dicionário."""

    def __init__(self, inventario: Inventario):
        self.inventario = inventario
        self.opcoes = {
            "1": ("Cadastrar Ativo", self.cadastrar_ativo),
            "2": ("Buscar Ativo por ID", self.buscar_por_id),
            "3": ("Buscar Ativo por Hostname", self.buscar_por_hostname),
            "4": ("Atualizar Ativo", self.atualizar_ativo),
            "5": ("Deletar Ativo", self.deletar_ativo),
            "6": ("Cadastrar Vulnerabilidade em Ativo", self.cadastrar_vulnerabilidade),
            "7": ("Listar Vulnerabilidades de um Ativo", self.listar_vulnerabilidades),
            "8": ("Listar Todos os Ativos", self.listar_ativos),
            "9": ("Atualizar Status / Remover Vulnerabilidade", self.menu_tratamento),
            "10": ("Dependências entre Ativos", self.menu_dependencias),
            "11": ("Análise de Risco (risco próprio e efetivo)", self.analise_risco),
        }

    # ------------------------------------------------------------------
    # Laço principal
    # ------------------------------------------------------------------
    def executar(self) -> None:
        for aviso in self.inventario.avisos:
            print(f"Aviso: {aviso}")
        while True:
            print("\n" + "=" * 55)
            print("   SISTEMA DE INVENTÁRIO E GESTÃO DE VULNERABILIDADES")
            print("=" * 55)
            for chave, (titulo, _) in self.opcoes.items():
                print(f"{chave:>2} - {titulo}")
            print(" 0 - Sair")
            print("=" * 55)
            escolha = input("Selecione uma opção: ").strip()
            if escolha == "0":
                print("[+] Dados já gravados em disco. Encerrando o sistema...")
                return
            self._executar_opcao(self.opcoes, escolha)

    @staticmethod
    def _executar_opcao(opcoes: dict, escolha: str) -> None:
        """Executa a opção tratando erros, para que nenhuma falha derrube o programa."""
        if escolha not in opcoes:
            print("Opção inválida. Selecione uma opção válida do menu.")
            return
        try:
            opcoes[escolha][1]()
        except Cancelado:
            print("  Operação cancelada.")
        except (ErroInventario, ValueError) as erro:
            print(f"Erro: {erro}")
        except ErroPersistencia as erro:
            print(f"Erro ao salvar os dados: {erro}")

    def _submenu(self, titulo: str, opcoes: dict) -> None:
        while True:
            print(f"\n--- {titulo} ---")
            for chave, (texto, _) in opcoes.items():
                print(f"{chave} - {texto}")
            print("0 - Voltar")
            escolha = input("Selecione uma opção: ").strip()
            if escolha == "0":
                return
            self._executar_opcao(opcoes, escolha)

    def _selecionar_ativo(self, rotulo: str = "ID ou hostname do ativo") -> Equipamento:
        return self.inventario.buscar(Entrada.texto(rotulo))

    # ------------------------------------------------------------------
    # CRUD de ativos
    # ------------------------------------------------------------------
    def cadastrar_ativo(self) -> None:
        print("\n[Cadastro de ativo]  (digite 'c' a qualquer momento para cancelar)")
        # Verifica duplicidade logo na digitação, sem fazer o usuário preencher tudo antes
        while True:
            id_ativo = Entrada.inteiro("ID do Ativo (Enter aceita o sugerido)", minimo=1,
                                       padrao=self.inventario.proximo_id())
            if not self.inventario.existe_id(id_ativo):
                break
            print(f"  ! O identificador {id_ativo} já está em uso.")
        while True:
            hostname = Entrada.texto("Hostname")
            if not self.inventario.existe_hostname(hostname):
                break
            print(f"  ! O hostname '{hostname}' já está em uso.")
        responsavel = Entrada.texto("Responsável (sem números)", validador=validar_responsavel)
        localizacao = Entrada.texto("Localização física/lógica")
        descricao = Entrada.texto("Descrição (opcional)", obrigatorio=False)
        tipo = Entrada.opcao_enum("\nTipos disponíveis:", TipoAtivo)

        ativo = criar_equipamento(tipo, id_ativo, hostname, responsavel, localizacao, descricao)
        while Entrada.confirmar("Adicionar uma vulnerabilidade inicial?"):
            try:
                vulnerabilidade = self._ler_vulnerabilidade(ativo)
                self.inventario.verificar_consistencia(vulnerabilidade)
                ativo.adicionar_vulnerabilidade(vulnerabilidade)
            except (ValueError, ErroInventario, Cancelado) as erro:
                print(f"  ! Vulnerabilidade não adicionada. {erro}")

        self.inventario.cadastrar_ativo(ativo)
        print(f"[+] Ativo cadastrado com sucesso ({len(ativo.vulnerabilidades)} "
              "vulnerabilidade(s)).")

    def buscar_por_id(self) -> None:
        ativo = self.inventario.buscar_por_id(Entrada.inteiro("ID do Ativo a buscar"))
        print()
        print(ativo)
        self._exibir_vulnerabilidades(ativo)

    def buscar_por_hostname(self) -> None:
        encontrados = self.inventario.buscar_por_trecho(Entrada.texto("Termo de busca no hostname"))
        if not encontrados:
            print("Nenhum ativo correspondente localizado.")
            return
        print(f"\nResultados encontrados ({len(encontrados)}):")
        for ativo in encontrados:
            print(ativo)

    def listar_ativos(self) -> None:
        ativos = self.inventario.ativos
        if not ativos:
            print("\nInventário vazio. Nenhum ativo registrado.")
            return
        print(f"\n--- Inventário Atual ({len(ativos)} ativos) ---")
        print(f"{'ID':>4}  {'Hostname':<20} {'Tipo':<17} {'Responsável':<18} {'Vulns':>5}")
        print("-" * 70)
        for a in ativos:
            print(f"{a.id_ativo:>4}  {a.hostname:<20} {a.tipo.rotulo:<17} "
                  f"{a.responsavel:<18} {len(a.vulnerabilidades):>5}")

    def atualizar_ativo(self) -> None:
        ativo = self.inventario.buscar_por_id(Entrada.inteiro("ID do Ativo a atualizar"))
        print(f"\n[Atualizar ativo {ativo.id_ativo}]  Enter mantém o valor atual.")
        hostname = Entrada.texto("Hostname", atual=ativo.hostname)
        responsavel = Entrada.texto("Responsável", atual=ativo.responsavel,
                                    validador=validar_responsavel)
        localizacao = Entrada.texto("Localização", atual=ativo.localizacao)
        descricao = Entrada.texto("Descrição", atual=ativo.descricao or "-")
        tipo = Entrada.opcao_enum(f"Tipo (atual: {ativo.tipo.rotulo}):", TipoAtivo,
                                  permitir_manter=True)

        ativo = self.inventario.atualizar_ativo(
            ativo.id_ativo, hostname, responsavel, localizacao, descricao, tipo
        )
        print("[+] Ativo atualizado com sucesso!")
        print(ativo)

    def deletar_ativo(self) -> None:
        ativo = self.inventario.buscar_por_id(Entrada.inteiro("ID do Ativo a deletar"))
        print(ativo)
        aviso = (f"Remover o ativo, suas {len(ativo.vulnerabilidades)} vulnerabilidade(s) "
                 "e as dependências ligadas a ele?")
        if Entrada.confirmar(aviso):
            self.inventario.remover_ativo(ativo.id_ativo)
            print("[+] Ativo e vulnerabilidades removidos com sucesso.")
        else:
            print("Remoção cancelada.")

    # ------------------------------------------------------------------
    # Vulnerabilidades
    # ------------------------------------------------------------------
    def _ler_vulnerabilidade(self, ativo: Equipamento) -> Vulnerabilidade:
        sugestao = self.inventario.proximo_id_vulnerabilidade()
        # Evita sugerir um identificador que já está neste ativo (cadastro com várias iniciais)
        numero = int(sugestao.split("-")[1])
        while ativo.buscar_vulnerabilidade(sugestao) is not None:
            numero += 1
            sugestao = f"VULN-{numero:03d}"

        identificador = Entrada.texto(f"Identificador (CVE ou Enter para {sugestao})",
                                      obrigatorio=False) or sugestao
        descricao = Entrada.texto("Descrição da vulnerabilidade")
        categoria = Entrada.texto("Categoria (ex: Configuração, Software)")
        severidade = Entrada.opcao_enum("\nSeveridades disponíveis:", Severidade)
        minimo, maximo = severidade.faixa_cvss
        cvss = Entrada.decimal(
            f"Nota CVSS entre {minimo} e {maximo} (Enter usa {severidade.cvss_padrao})",
            obrigatorio=False,
        )
        status = Entrada.opcao_enum("\nStatus disponíveis:", StatusTratamento)
        return Vulnerabilidade(identificador, descricao, categoria, severidade, status, cvss)

    def cadastrar_vulnerabilidade(self) -> None:
        ativo = self.inventario.buscar_por_id(Entrada.inteiro("ID do Ativo"))
        self.inventario.adicionar_vulnerabilidade(ativo.id_ativo, self._ler_vulnerabilidade(ativo))
        print("[+] Vulnerabilidade registrada com sucesso!")

    def listar_vulnerabilidades(self) -> None:
        ativo = self.inventario.buscar_por_id(Entrada.inteiro("ID do Ativo para consulta"))
        self._exibir_vulnerabilidades(ativo)

    @staticmethod
    def _exibir_vulnerabilidades(ativo: Equipamento) -> None:
        print(f"\n=== VULNERABILIDADES DO ATIVO {ativo.id_ativo} ({ativo.hostname}) ===")
        vulnerabilidades = ativo.vulnerabilidades
        if not vulnerabilidades:
            print("Ativo sem vulnerabilidades registradas.")
            return
        for vuln in vulnerabilidades:
            print(f"  - {vuln}")

    def menu_tratamento(self) -> None:
        self._submenu("Tratamento de Vulnerabilidades", {
            "1": ("Atualizar status de tratamento", self.atualizar_status),
            "2": ("Remover vulnerabilidade de um ativo", self.remover_vulnerabilidade),
        })

    def atualizar_status(self) -> None:
        ativo = self.inventario.buscar_por_id(Entrada.inteiro("ID do Ativo"))
        self._exibir_vulnerabilidades(ativo)
        if not ativo.vulnerabilidades:
            return
        identificador = Entrada.texto("Identificador da vulnerabilidade")
        status = Entrada.opcao_enum("\nNovo status:", StatusTratamento)
        self.inventario.atualizar_status_vulnerabilidade(ativo.id_ativo, identificador, status)
        print("[+] Status atualizado.")

    def remover_vulnerabilidade(self) -> None:
        ativo = self.inventario.buscar_por_id(Entrada.inteiro("ID do Ativo"))
        self._exibir_vulnerabilidades(ativo)
        if not ativo.vulnerabilidades:
            return
        identificador = Entrada.texto("Identificador da vulnerabilidade")
        self.inventario.remover_vulnerabilidade(ativo.id_ativo, identificador)
        print("[+] Vulnerabilidade removida.")

    # ------------------------------------------------------------------
    # Dependências
    # ------------------------------------------------------------------
    def menu_dependencias(self) -> None:
        self._submenu("Dependências entre Ativos", {
            "1": ("Cadastrar/atualizar dependência", self.cadastrar_dependencia),
            "2": ("Listar dependências", self.listar_dependencias),
            "3": ("Remover dependência", self.remover_dependencia),
        })

    def cadastrar_dependencia(self) -> None:
        print("\nO ativo de DESTINO herda uma fração do risco do ativo de ORIGEM.")
        print("Ex.: um notebook (destino) herda 50% do risco do servidor (origem).")
        origem = self._selecionar_ativo("Ativo de ORIGEM (ID ou hostname)")
        destino = self._selecionar_ativo("Ativo de DESTINO (ID ou hostname)")
        disponivel = 1 - self.inventario.soma_linha(destino.id_ativo, origem.id_ativo)
        fracao = Entrada.decimal(f"Fração herdada, de 0 até menos de {disponivel:.2f}")
        dependencia = self.inventario.cadastrar_dependencia(
            origem.id_ativo, destino.id_ativo, fracao
        )
        print(f"[+] Dependência registrada: {dependencia}.")

    def listar_dependencias(self) -> None:
        dependencias = self.inventario.dependencias
        if not dependencias:
            print("Nenhuma dependência cadastrada.")
            return
        for dep in dependencias:
            print(f"  - {dep}")

    def remover_dependencia(self) -> None:
        origem = self._selecionar_ativo("Ativo de ORIGEM (ID ou hostname)")
        destino = self._selecionar_ativo("Ativo de DESTINO (ID ou hostname)")
        self.inventario.remover_dependencia(origem.id_ativo, destino.id_ativo)
        print("[+] Dependência removida.")

    # ------------------------------------------------------------------
    # Análise de risco
    # ------------------------------------------------------------------
    def analise_risco(self) -> None:
        modelo = ModeloAnaliseRisco(self.inventario.ativos, self.inventario.dependencias)
        if modelo.n == 0:
            print("Nenhum ativo cadastrado para analisar.")
            return
        resultados, diagnostico = modelo.calcular()

        print(f"\nEquipamentos (n) = {modelo.n} | Vulnerabilidades distintas (m) = {modelo.m}")
        print(f"det(I - A) = {diagnostico.determinante:.4f} | "
              f"número de condição = {diagnostico.numero_condicao:.4g}")
        print(diagnostico.mensagem)

        print(f"\n{'ID':>4}  {'Hostname':<20} {'Tipo':<17} {'Risco próprio':>13} "
              f"{'Risco efetivo':>14}")
        print("-" * 72)
        for r in resultados:
            efetivo = "não calculado" if r.risco_efetivo is None else f"{r.risco_efetivo:.2f}"
            print(f"{r.equipamento.id_ativo:>4}  {r.equipamento.hostname:<20} "
                  f"{r.equipamento.tipo.rotulo:<17} {r.risco_proprio:>13.2f} {efetivo:>14}")

        if Entrada.confirmar("\nExibir as matrizes do modelo (M, v, A)?"):
            with np.printoptions(precision=2, suppress=True):
                print(f"\nOrdem das linhas (IDs): {[eq.id_ativo for eq in modelo.equipamentos]}")
                print(f"Colunas de M (vulnerabilidades): {list(modelo.indice_vulnerabilidade)}")
                print(f"\nM (incidência, {modelo.n}x{modelo.m}):\n{modelo.matriz_incidencia()}")
                print(f"\nv (severidade CVSS):\n{modelo.vetor_severidade()}")
                print(f"\nA (dependências, {modelo.n}x{modelo.n}):\n{modelo.A}")


def main() -> None:
    # A pasta de dados pode ser trocada por variável de ambiente (útil no Docker, Sprint 4)
    pasta_dados = os.environ.get("INVENTARIO_DADOS", "dados")
    try:
        AplicacaoCLI(Inventario(pasta_dados)).executar()
    except (EOFError, KeyboardInterrupt):
        # Ctrl+C, Ctrl+D ou entrada encerrada: sai sem mostrar erro técnico
        print("\nEntrada encerrada. Programa finalizado.")
        sys.exit(0)


if __name__ == "__main__":
    main()