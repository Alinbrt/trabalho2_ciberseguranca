"""Classes de domínio: Vulnerabilidade, Equipamento (e subclasses) e Dependencia."""

from abc import ABC, abstractmethod

from enums import Severidade, StatusTratamento, TipoAtivo


def _texto_obrigatorio(valor, campo: str) -> str:
    """Impede um campo vazio e retorna o texto sem espaços nas pontas."""
    if not isinstance(valor, str) or not valor.strip():
        raise ValueError(f"O campo '{campo}' é obrigatório.")
    return valor.strip()


def validar_responsavel(nome) -> str:
    # Lista de permissão: aceito só o que é válido num nome de pessoa.
    # Assim barro injeção (ex: <script>) e textos gigantes, não só números.
    nome = _texto_obrigatorio(nome, "responsável")
    if len(nome) < 2 or len(nome) > 100:
        raise ValueError("O responsável deve ter entre 2 e 100 caracteres.")
    for caractere in nome:
        if not (caractere.isalpha() or caractere in " -'"):
            raise ValueError("O responsável só pode ter letras, espaço, hífen e apóstrofo.")
    return nome


def _inteiro_positivo(valor, campo: str) -> int:
    # O identificador precisa ser um número inteiro maior que zero.
    if not isinstance(valor, int) or valor <=0:
        raise ValueError(f"O campo '{campo}' deve ser um número inteiro positivo.")
    return valor

class Vulnerabilidade:
    """Representa uma fraqueza de um ativo que pode ser explorada."""

    def __init__(
        self,
        cve: str,
        descricao: str,
        categoria: str,
        severidade: Severidade,
        status: StatusTratamento = StatusTratamento.ABERTA,
        cvss: float | None = None,
    ):
        self.cve = _texto_obrigatorio(cve, "identificador (CVE)").upper()
        self.descricao = _texto_obrigatorio(descricao, "descrição")
        self.categoria = _texto_obrigatorio(categoria, "categoria")
        if not isinstance(severidade, Severidade):
            raise ValueError("Severidade inválida.")
        if not isinstance(status, StatusTratamento):
            raise ValueError("Status de tratamento inválido.")
        self.severidade = severidade
        self.status = status
        self.cvss = self._definir_cvss(cvss)

    def _definir_cvss(self, cvss: float | None) -> float:
        """Usa o CVSS informado (se coerente com a severidade) ou o padrão da faixa."""
        if cvss is None:
            return self.severidade.cvss_padrao
        cvss = float(cvss)
        minimo, maximo = self.severidade.faixa_cvss
        if not minimo <= cvss <= maximo:
            raise ValueError(
                f"CVSS {cvss} incompatível com severidade {self.severidade.value} "
                f"(faixa {minimo}–{maximo})."
            )
        return cvss

    def atualizar_status(self, novo_status: StatusTratamento) -> None:
        """Regra de negócio: 'Corrigida' é um status terminal."""
        if self.status == StatusTratamento.CORRIGIDA:
            raise ValueError("Vulnerabilidade já corrigida: o status não pode mais ser alterado.")
        self.status = novo_status

    def to_dict(self) -> dict:
        return {
            "cve": self.cve,
            "descricao": self.descricao,
            "categoria": self.categoria,
            "severidade": self.severidade.value,
            "status": self.status.value,
            "cvss": self.cvss,
        }

    @classmethod
    def from_dict(cls, dados: dict) -> "Vulnerabilidade":
        return cls(
            cve=dados["cve"],
            descricao=dados["descricao"],
            categoria=dados["categoria"],
            severidade=Severidade(dados["severidade"]),
            status=StatusTratamento(dados["status"]),
            cvss=dados.get("cvss"),
        )

    def __str__(self) -> str:
        return (
            f"[{self.cve}] {self.descricao} | Categoria: {self.categoria} | "
            f"Severidade: {self.severidade.value} (CVSS {self.cvss:.1f}) | "
            f"Status: {self.status.value}"
        )


class Equipamento(ABC):
    """Representa um ativo de TI, peça central que guarda seus dados e vulnerabilidades"""

    TIPO: TipoAtivo  # definido em cada subclasse

    def __init__(
        self,
        id_ativo: int,
        hostname: str,
        responsavel: str,
        localizacao: str,
        descricao: str = "",
    ):
        self._id_ativo = _inteiro_positivo(id_ativo, "identificador")
        self.hostname = hostname          # passa pela validação do setter
        self.responsavel = responsavel
        self.localizacao = localizacao
        self.descricao = descricao
        # Dicionário CVE -> Vulnerabilidade: busca O(1) e impede CVE repetido no ativo
        self._vulnerabilidades: dict[str, Vulnerabilidade] = {}

    # --- Encapsulamento: atributos validados via property ----------------
    @property
    def id_ativo(self) -> int:
        """Identificador único: somente leitura depois de criado."""
        return self._id_ativo

    @property
    def hostname(self) -> str:
        return self._hostname

    @hostname.setter
    def hostname(self, valor: str) -> None:
        self._hostname = _texto_obrigatorio(valor, "hostname")

    @property
    def responsavel(self) -> str:
        return self._responsavel

    @responsavel.setter
    def responsavel(self, valor: str) -> None:
        self._responsavel = validar_responsavel(valor)

    @property
    def localizacao(self) -> str:
        return self._localizacao

    @localizacao.setter
    def localizacao(self, valor: str) -> None:
        self._localizacao = _texto_obrigatorio(valor, "localização")

    @property
    def descricao(self) -> str:
        return self._descricao

    @descricao.setter
    def descricao(self, valor: str) -> None:
        self._descricao = (valor or "").strip()

    @property
    def tipo(self) -> TipoAtivo:
        return self.TIPO

    @property
    def vulnerabilidades(self) -> list[Vulnerabilidade]:
        """Cópia da lista: quem está de fora não altera o dicionário interno."""
        return list(self._vulnerabilidades.values())

    # --- Vulnerabilidades ---------------------------------------------------
    def adicionar_vulnerabilidade(self, vulnerabilidade: Vulnerabilidade) -> None:
        if vulnerabilidade.cve in self._vulnerabilidades:
            raise ValueError(f"O ativo já possui a vulnerabilidade {vulnerabilidade.cve}.")
        self._vulnerabilidades[vulnerabilidade.cve] = vulnerabilidade

    def buscar_vulnerabilidade(self, cve: str) -> Vulnerabilidade | None:
        return self._vulnerabilidades.get(cve.strip().upper())

    def remover_vulnerabilidade(self, cve: str) -> bool:
        return self._vulnerabilidades.pop(cve.strip().upper(), None) is not None

    # --- Polimorfismo -------------------------------------------------------
    @abstractmethod
    def fator_exposicao(self) -> float:
        """Peso do tipo de ativo no risco próprio: b_i = (1 + fator) * (M v)_i."""

    def com_novo_tipo(self, novo_tipo: TipoAtivo) -> "Equipamento":
        """Trocar o tipo exige trocar a classe: cria o objeto da subclasse certa
        mantendo os dados e as vulnerabilidades."""
        novo = criar_equipamento(
            novo_tipo, self.id_ativo, self.hostname, self.responsavel,
            self.localizacao, self.descricao,
        )
        novo._vulnerabilidades = dict(self._vulnerabilidades)
        return novo

    # --- Serialização -------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "id": self.id_ativo,
            "hostname": self.hostname,
            "responsavel": self.responsavel,
            "localizacao": self.localizacao,
            "descricao": self.descricao,
            "tipo": self.tipo.name,
            "tipo_codigo": self.tipo.value,
            "vulnerabilidades": [v.to_dict() for v in self.vulnerabilidades],
        }

    @staticmethod
    def from_dict(dados: dict) -> "Equipamento":
        equipamento = criar_equipamento(
            TipoAtivo(dados["tipo_codigo"]),
            dados["id"],
            dados["hostname"],
            dados["responsavel"],
            dados["localizacao"],
            dados.get("descricao", ""),
        )
        for v_dados in dados.get("vulnerabilidades", []):
            equipamento.adicionar_vulnerabilidade(Vulnerabilidade.from_dict(v_dados))
        return equipamento

    def __str__(self) -> str:
        texto = (
            f"ID {self.id_ativo} | {self.hostname} | Tipo: {self.tipo.rotulo} "
            f"(código {self.tipo.value})\n"
            f"   Responsável: {self.responsavel} | Localização: {self.localizacao}"
        )
        if self.descricao:
            texto += f"\n   Descrição: {self.descricao}"
        return texto


class Notebook(Equipamento):
    TIPO = TipoAtivo.NOTEBOOK

    def fator_exposicao(self) -> float:
        return 0.05  # dispositivo de borda: exposição lateral contida


class Servidor(Equipamento):
    TIPO = TipoAtivo.SERVIDOR

    def fator_exposicao(self) -> float:
        return 0.20  # ativo central: alto impacto se comprometido


class Roteador(Equipamento):
    TIPO = TipoAtivo.ROTEADOR

    def fator_exposicao(self) -> float:
        return 0.30  # gateway: ponto crítico de passagem de tráfego


class EstacaoTrabalho(Equipamento):
    TIPO = TipoAtivo.ESTACAO_TRABALHO

    def fator_exposicao(self) -> float:
        return 0.10  # endpoint fixo: exposição padrão


class AplicacaoWeb(Equipamento):
    TIPO = TipoAtivo.APLICACAO_WEB

    def fator_exposicao(self) -> float:
        return 0.25  # exposta à internet: superfície de ataque ampla


class BancoDeDados(Equipamento):
    TIPO = TipoAtivo.BANCO_DE_DADOS

    def fator_exposicao(self) -> float:
        return 0.20  # guarda dados sensíveis: alto impacto se comprometido


# Fábrica: dicionário tipo -> classe. Novo tipo = nova subclasse + uma linha aqui.
CLASSES_POR_TIPO: dict[TipoAtivo, type[Equipamento]] = {
    TipoAtivo.NOTEBOOK: Notebook,
    TipoAtivo.SERVIDOR: Servidor,
    TipoAtivo.ROTEADOR: Roteador,
    TipoAtivo.ESTACAO_TRABALHO: EstacaoTrabalho,
    TipoAtivo.APLICACAO_WEB: AplicacaoWeb,
    TipoAtivo.BANCO_DE_DADOS: BancoDeDados,
}


def criar_equipamento(
    tipo: TipoAtivo,
    id_ativo: int,
    hostname: str,
    responsavel: str,
    localizacao: str,
    descricao: str = "",
) -> Equipamento:
    """Instancia a subclasse correspondente ao tipo informado."""
    classe = CLASSES_POR_TIPO[tipo]
    return classe(id_ativo, hostname, responsavel, localizacao, descricao)


class Dependencia:
    """Fração do risco do ativo de ORIGEM (j) transmitida ao ativo de DESTINO (i).

    Corresponde a A[i][j] = fracao no modelo x = b + A x.
    """

    def __init__(self, id_origem: int, id_destino: int, fracao: float):
        self.id_origem = _inteiro_positivo(id_origem, "ativo de origem")
        self.id_destino = _inteiro_positivo(id_destino, "ativo de destino")
        if self.id_origem == self.id_destino:
            raise ValueError("Um ativo não pode depender de si mesmo (A_ii = 0).")
        fracao = float(fracao)
        if not 0 <= fracao < 1:
            raise ValueError("A fração deve estar no intervalo [0, 1).")
        self.fracao = fracao

    @property
    def chave(self) -> tuple[int, int]:
        return (self.id_origem, self.id_destino)

    def to_dict(self) -> dict:
        return {"id_origem": self.id_origem, "id_destino": self.id_destino, "fracao": self.fracao}

    @classmethod
    def from_dict(cls, dados: dict) -> "Dependencia":
        return cls(dados["id_origem"], dados["id_destino"], dados["fracao"])

    def __str__(self) -> str:
        return (
            f"Ativo {self.id_destino} herda {self.fracao:.0%} do risco do ativo {self.id_origem}"
        )