"""Regras de negócio do inventário: CRUD de ativos, vulnerabilidades e dependências."""

import os

from enums import StatusTratamento, TipoAtivo
from modelos import Dependencia, Equipamento, Vulnerabilidade
from persistencia import ErroPersistencia, RepositorioJSON


class ErroInventario(Exception):
    """Operação inválida no inventário (ativo inexistente, duplicado etc.)."""


class Inventario:
    """Mantém os ativos em memória (indexados por dicionário) e sincroniza com o JSON."""

    def __init__(self, pasta_dados: str = "dados"):
        self._repo_ativos = RepositorioJSON(os.path.join(pasta_dados, "inventario_ativos.json"))
        self._repo_dependencias = RepositorioJSON(
            os.path.join(pasta_dados, "dependencias_rede.json")
        )

        # Índices em dicionário (hash map): busca por ID ou hostname em O(1)
        self._ativos: dict[int, Equipamento] = {}
        self._id_por_hostname: dict[str, int] = {}
        # Chave (id_origem, id_destino) impede dependência duplicada
        self._dependencias: dict[tuple[int, int], Dependencia] = {}

        self.avisos: list[str] = []  # problemas encontrados no carregamento
        self._carregar()

    # ------------------------------------------------------------------
    # Carregamento e gravação
    # ------------------------------------------------------------------
    def _carregar(self) -> None:
        for registro in self._ler(self._repo_ativos):
            try:
                self._indexar(Equipamento.from_dict(registro))
            except (KeyError, ValueError, TypeError, AttributeError, ErroInventario) as erro:
                self.avisos.append(f"Ativo ignorado no carregamento ({erro}).")

        for registro in self._ler(self._repo_dependencias):
            try:
                dep = Dependencia.from_dict(registro)
                if dep.id_origem not in self._ativos or dep.id_destino not in self._ativos:
                    raise ErroInventario("referencia um ativo inexistente")
                self._dependencias[dep.chave] = dep
            except (KeyError, ValueError, TypeError, AttributeError, ErroInventario) as erro:
                self.avisos.append(f"Dependência ignorada no carregamento ({erro}).")

    def _ler(self, repositorio: RepositorioJSON) -> list[dict]:
        try:
            return repositorio.carregar()
        except ErroPersistencia as erro:
            self.avisos.append(str(erro))
            return []

    def _salvar(self) -> None:
        self._repo_ativos.salvar([a.to_dict() for a in self.ativos])
        self._repo_dependencias.salvar([d.to_dict() for d in self.dependencias])

    def _indexar(self, ativo: Equipamento) -> None:
        if ativo.id_ativo in self._ativos:
            raise ErroInventario(f"Já existe um ativo com ID {ativo.id_ativo}.")
        chave_host = ativo.hostname.lower()
        if chave_host in self._id_por_hostname:
            raise ErroInventario(f"Já existe um ativo com hostname '{ativo.hostname}'.")
        self._ativos[ativo.id_ativo] = ativo
        self._id_por_hostname[chave_host] = ativo.id_ativo

    # ------------------------------------------------------------------
    # Consultas
    # ------------------------------------------------------------------
    @property
    def ativos(self) -> list[Equipamento]:
        """Ativos ordenados por ID (a ordem define as linhas das matrizes)."""
        return [self._ativos[i] for i in sorted(self._ativos)]

    @property
    def dependencias(self) -> list[Dependencia]:
        return sorted(self._dependencias.values(), key=lambda d: (d.id_destino, d.id_origem))

    def existe_id(self, id_ativo: int) -> bool:
        return id_ativo in self._ativos

    def existe_hostname(self, hostname: str) -> bool:
        return hostname.strip().lower() in self._id_por_hostname

    def proximo_id(self) -> int:
        return max(self._ativos, default=0) + 1

    def buscar_por_id(self, id_ativo: int) -> Equipamento:
        """Acesso direto pela chave do dicionário: O(1)."""
        try:
            return self._ativos[id_ativo]
        except KeyError:
            raise ErroInventario(f"Nenhum ativo com ID {id_ativo}.") from None

    def buscar_por_hostname(self, hostname: str) -> Equipamento:
        """Hostname exato, pelo índice secundário em dicionário: O(1)."""
        id_ativo = self._id_por_hostname.get(hostname.strip().lower())
        if id_ativo is None:
            raise ErroInventario(f"Nenhum ativo com hostname '{hostname}'.")
        return self._ativos[id_ativo]

    def buscar_por_trecho(self, termo: str) -> list[Equipamento]:
        """Ativos cujo hostname contém o termo (como no Trabalho 1): varredura O(n)."""
        termo = termo.strip().lower()
        return [a for a in self.ativos if termo in a.hostname.lower()]

    def buscar(self, termo: str) -> Equipamento:
        """Busca pelo ID se o termo for numérico; senão, pelo hostname exato."""
        termo = termo.strip()
        if termo.isdigit():
            return self.buscar_por_id(int(termo))
        return self.buscar_por_hostname(termo)

    # ------------------------------------------------------------------
    # CRUD de ativos
    # ------------------------------------------------------------------
    def cadastrar_ativo(self, ativo: Equipamento) -> None:
        for vulnerabilidade in ativo.vulnerabilidades:
            self.verificar_consistencia(vulnerabilidade)
        self._indexar(ativo)
        self._salvar()

    def atualizar_ativo(
        self,
        id_ativo: int,
        hostname: str | None = None,
        responsavel: str | None = None,
        localizacao: str | None = None,
        descricao: str | None = None,
        tipo: TipoAtivo | None = None,
    ) -> Equipamento:
        """Atualiza só os campos informados (None = manter o valor atual)."""
        ativo = self.buscar_por_id(id_ativo)

        # Valida tudo antes de alterar qualquer campo (evita atualização pela metade)
        for campo, valor in (("hostname", hostname), ("responsável", responsavel),
                             ("localização", localizacao)):
            if valor is not None and not valor.strip():
                raise ErroInventario(f"O campo '{campo}' não pode ficar vazio.")
        if (hostname is not None and hostname.strip().lower() != ativo.hostname.lower()
                and self.existe_hostname(hostname)):
            raise ErroInventario(f"Já existe um ativo com hostname '{hostname}'.")
        if responsavel is not None:
            ativo.responsavel = responsavel  # o setter aplica a regra do responsável

        if hostname is not None:
            del self._id_por_hostname[ativo.hostname.lower()]
            ativo.hostname = hostname
            self._id_por_hostname[ativo.hostname.lower()] = id_ativo
        if localizacao is not None:
            ativo.localizacao = localizacao
        if descricao is not None:
            ativo.descricao = descricao
        if tipo is not None and tipo != ativo.tipo:
            ativo = ativo.com_novo_tipo(tipo)  # novo objeto da subclasse correta
            self._ativos[id_ativo] = ativo

        self._salvar()
        return ativo

    def remover_ativo(self, id_ativo: int) -> Equipamento:
        """Remove o ativo, suas vulnerabilidades e as dependências que o citam."""
        ativo = self.buscar_por_id(id_ativo)
        del self._ativos[id_ativo]
        del self._id_por_hostname[ativo.hostname.lower()]
        self._dependencias = {
            chave: dep for chave, dep in self._dependencias.items() if id_ativo not in chave
        }
        self._salvar()
        return ativo

    # ------------------------------------------------------------------
    # Vulnerabilidades
    # ------------------------------------------------------------------
    def _vulnerabilidade_existente(self, identificador: str) -> Vulnerabilidade | None:
        """Procura o identificador em qualquer ativo do inventário."""
        for ativo in self._ativos.values():
            encontrada = ativo.buscar_vulnerabilidade(identificador)
            if encontrada is not None:
                return encontrada
        return None

    def verificar_consistencia(self, vulnerabilidade: Vulnerabilidade) -> None:
        """O mesmo identificador em ativos diferentes é a MESMA vulnerabilidade
        (mesma coluna j de M), então precisa ter a mesma nota CVSS (mesmo v_j)."""
        existente = self._vulnerabilidade_existente(vulnerabilidade.cve)
        if existente is not None and existente.cvss != vulnerabilidade.cvss:
            raise ErroInventario(
                f"{vulnerabilidade.cve} já existe no inventário com CVSS {existente.cvss} "
                f"({existente.severidade.value}). Use a mesma nota ou outro identificador."
            )

    def proximo_id_vulnerabilidade(self) -> str:
        """Gera um identificador VULN-NNN ainda não usado em nenhum ativo."""
        numero = 1
        while self._vulnerabilidade_existente(f"VULN-{numero:03d}") is not None:
            numero += 1
        return f"VULN-{numero:03d}"

    def adicionar_vulnerabilidade(self, id_ativo: int, vulnerabilidade: Vulnerabilidade) -> None:
        ativo = self.buscar_por_id(id_ativo)
        self.verificar_consistencia(vulnerabilidade)
        ativo.adicionar_vulnerabilidade(vulnerabilidade)
        self._salvar()

    def atualizar_status_vulnerabilidade(
        self, id_ativo: int, identificador: str, novo_status: StatusTratamento
    ) -> Vulnerabilidade:
        vulnerabilidade = self.buscar_por_id(id_ativo).buscar_vulnerabilidade(identificador)
        if vulnerabilidade is None:
            raise ErroInventario(f"O ativo {id_ativo} não possui a vulnerabilidade {identificador}.")
        vulnerabilidade.atualizar_status(novo_status)
        self._salvar()
        return vulnerabilidade

    def remover_vulnerabilidade(self, id_ativo: int, identificador: str) -> None:
        if not self.buscar_por_id(id_ativo).remover_vulnerabilidade(identificador):
            raise ErroInventario(f"O ativo {id_ativo} não possui a vulnerabilidade {identificador}.")
        self._salvar()

    # ------------------------------------------------------------------
    # Dependências (matriz A)
    # ------------------------------------------------------------------
    def soma_linha(self, id_destino: int, ignorar_origem: int | None = None) -> float:
        """Soma das frações herdadas pelo ativo de destino (soma da linha i de A)."""
        return sum(
            dep.fracao for dep in self._dependencias.values()
            if dep.id_destino == id_destino and dep.id_origem != ignorar_origem
        )

    def cadastrar_dependencia(self, id_origem: int, id_destino: int, fracao: float) -> Dependencia:
        """Cadastra (ou atualiza) uma dependência mantendo a soma de cada linha de A < 1.

        Com essa regra, I - A é estritamente diagonal dominante e, portanto, invertível.
        """
        self.buscar_por_id(id_origem)
        self.buscar_por_id(id_destino)
        dependencia = Dependencia(id_origem, id_destino, fracao)  # valida A_ii = 0 e [0, 1)

        nova_soma = self.soma_linha(id_destino, ignorar_origem=id_origem) + dependencia.fracao
        if nova_soma >= 1:
            raise ErroInventario(
                f"A soma das frações herdadas pelo ativo {id_destino} ficaria {nova_soma:.2f} "
                "(precisa ser < 1 para manter I - A diagonal dominante)."
            )
        self._dependencias[dependencia.chave] = dependencia
        self._salvar()
        return dependencia

    def remover_dependencia(self, id_origem: int, id_destino: int) -> None:
        if self._dependencias.pop((id_origem, id_destino), None) is None:
            raise ErroInventario("Dependência não encontrada.")
        self._salvar()