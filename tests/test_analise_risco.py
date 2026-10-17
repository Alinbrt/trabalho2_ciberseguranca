"""Testes do modelo de risco e do inventário. Rodar com:  python -m unittest -v"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analise_risco import ModeloAnaliseRisco  # noqa: E402
from enums import Severidade, StatusTratamento, TipoAtivo  # noqa: E402
from inventario import ErroInventario, Inventario  # noqa: E402
from modelos import Dependencia, Vulnerabilidade, criar_equipamento  # noqa: E402


def vuln(cve, severidade, cvss, status=StatusTratamento.ABERTA):
    return Vulnerabilidade(cve, "teste", "teste", severidade, status, cvss)


def cenario_manual():
    """Cenário resolvido à mão (3 equipamentos, sem ciclos de dependência).

    b1 = 8,0 x 1,20 = 9,60   b2 = 5,5 x 1,30 = 7,15   b3 = 2,0 x 1,05 = 2,10
    A[1][2] = 0,4 (servidor herda do roteador), A[3][1] = 0,5 (notebook herda do servidor)
    x2 = 7,15   x1 = 9,60 + 0,4 x 7,15 = 12,46   x3 = 2,10 + 0,5 x 12,46 = 8,33
    """
    servidor = criar_equipamento(TipoAtivo.SERVIDOR, 1, "srv-01", "Ana", "Datacenter")
    roteador = criar_equipamento(TipoAtivo.ROTEADOR, 2, "rt-01", "Bruno", "Rack 2")
    notebook = criar_equipamento(TipoAtivo.NOTEBOOK, 3, "nb-01", "Carla", "RH")
    servidor.adicionar_vulnerabilidade(vuln("CVE-A", Severidade.ALTA, 8.0))
    roteador.adicionar_vulnerabilidade(vuln("CVE-B", Severidade.MEDIA, 5.5))
    notebook.adicionar_vulnerabilidade(vuln("CVE-C", Severidade.BAIXA, 2.0))
    dependencias = [Dependencia(2, 1, 0.4), Dependencia(1, 3, 0.5)]
    return [servidor, roteador, notebook], dependencias


class TestModeloRisco(unittest.TestCase):
    def test_cenario_resolvido_a_mao(self):
        equipamentos, dependencias = cenario_manual()
        resultados, diagnostico = ModeloAnaliseRisco(equipamentos, dependencias).calcular()

        self.assertTrue(diagnostico.invertivel)
        self.assertTrue(diagnostico.diagonal_dominante)
        self.assertAlmostEqual(diagnostico.determinante, 1.0)
        for r, proprio, efetivo in zip(resultados, [9.60, 7.15, 2.10], [12.46, 7.15, 8.33]):
            self.assertAlmostEqual(r.risco_proprio, proprio)
            self.assertAlmostEqual(r.risco_efetivo, efetivo)

    def test_status_e_por_ativo(self):
        """Mesmo CVE corrigido em um ativo e aberto em outro."""
        a = criar_equipamento(TipoAtivo.ESTACAO_TRABALHO, 1, "ws-1", "Xavier", "Sala 1")
        b = criar_equipamento(TipoAtivo.ESTACAO_TRABALHO, 2, "ws-2", "Xavier", "Sala 1")
        a.adicionar_vulnerabilidade(vuln("CVE-X", Severidade.ALTA, 8.0, StatusTratamento.CORRIGIDA))
        b.adicionar_vulnerabilidade(vuln("CVE-X", Severidade.ALTA, 8.0, StatusTratamento.ABERTA))
        resultados, _ = ModeloAnaliseRisco([a, b], []).calcular()
        self.assertEqual(resultados[0].risco_proprio, 0.0)
        self.assertAlmostEqual(resultados[1].risco_proprio, 8.0 * 1.10)

    def test_sistema_singular_e_detectado(self):
        """Cada linha de A soma exatamente 1: I - A tem autovalor 0 (singular)."""
        eqs = [criar_equipamento(TipoAtivo.SERVIDOR, i, f"s{i}", "Xavier", "Sala 1") for i in (1, 2, 3)]
        deps = [Dependencia(o, d, 0.5) for o in (1, 2, 3) for d in (1, 2, 3) if o != d]
        resultados, diagnostico = ModeloAnaliseRisco(eqs, deps).calcular()
        self.assertFalse(diagnostico.invertivel)
        self.assertFalse(diagnostico.diagonal_dominante)
        self.assertTrue(all(r.risco_efetivo is None for r in resultados))

    def test_inventario_vazio(self):
        resultados, diagnostico = ModeloAnaliseRisco([], []).calcular()
        self.assertEqual(resultados, [])
        self.assertFalse(diagnostico.invertivel)


class TestModelos(unittest.TestCase):
    def test_cvss_padrao_e_faixa(self):
        self.assertEqual(Vulnerabilidade("V1", "d", "c", Severidade.MEDIA).cvss, 5.5)
        with self.assertRaises(ValueError):
            Vulnerabilidade("V1", "d", "c", Severidade.BAIXA, cvss=9.0)

    def test_corrigida_e_terminal(self):
        v = vuln("V1", Severidade.ALTA, 8.0, StatusTratamento.CORRIGIDA)
        with self.assertRaises(ValueError):
            v.atualizar_status(StatusTratamento.ABERTA)

    def test_dependencia_invalida(self):
        with self.assertRaises(ValueError):
            Dependencia(1, 1, 0.3)
        with self.assertRaises(ValueError):
            Dependencia(1, 2, 1.0)

    def test_regra_do_responsavel_do_trabalho_1(self):
        for invalido in ("", "A", "Ana2"):
            with self.assertRaises(ValueError):
                criar_equipamento(TipoAtivo.NOTEBOOK, 1, "nb", invalido, "Sala 1")

    def test_seis_tipos_com_fatores_proprios(self):
        fatores = {t: criar_equipamento(t, 1, "h", "Ana", "Sala").fator_exposicao()
                   for t in TipoAtivo}
        self.assertEqual(len(fatores), 6)
        self.assertEqual(fatores[TipoAtivo.APLICACAO_WEB], 0.25)

    def test_troca_de_tipo_troca_a_classe(self):
        nb = criar_equipamento(TipoAtivo.NOTEBOOK, 1, "nb", "Xavier", "Sala 1")
        nb.adicionar_vulnerabilidade(vuln("V1", Severidade.ALTA, 8.0))
        srv = nb.com_novo_tipo(TipoAtivo.SERVIDOR)
        self.assertEqual(type(srv).__name__, "Servidor")
        self.assertEqual(srv.fator_exposicao(), 0.20)
        self.assertEqual(len(srv.vulnerabilidades), 1)


class TestInventario(unittest.TestCase):
    def setUp(self):
        self.pasta = tempfile.TemporaryDirectory()
        self.inv = Inventario(self.pasta.name)
        equipamentos, _ = cenario_manual()
        for eq in equipamentos:
            self.inv.cadastrar_ativo(eq)

    def tearDown(self):
        self.pasta.cleanup()

    def test_persistencia_ida_e_volta(self):
        self.inv.cadastrar_dependencia(2, 1, 0.4)
        recarregado = Inventario(self.pasta.name)
        self.assertEqual([a.to_dict() for a in recarregado.ativos],
                         [a.to_dict() for a in self.inv.ativos])
        self.assertEqual(len(recarregado.dependencias), 1)
        self.assertEqual(recarregado.avisos, [])

    def test_busca_por_id_e_hostname(self):
        self.assertEqual(self.inv.buscar("2").hostname, "rt-01")
        self.assertEqual(self.inv.buscar("SRV-01").id_ativo, 1)

    def test_busca_por_trecho_do_hostname(self):
        self.assertEqual([a.id_ativo for a in self.inv.buscar_por_trecho("-01")], [1, 2, 3])
        self.assertEqual(self.inv.buscar_por_trecho("zzz"), [])

    def test_mesmo_identificador_exige_mesma_nota(self):
        with self.assertRaises(ErroInventario):
            self.inv.adicionar_vulnerabilidade(2, vuln("CVE-A", Severidade.ALTA, 7.5))
        self.inv.adicionar_vulnerabilidade(2, vuln("CVE-A", Severidade.ALTA, 8.0))
        self.assertEqual(self.inv.proximo_id_vulnerabilidade(), "VULN-001")

    def test_duplicados_sao_recusados(self):
        with self.assertRaises(ErroInventario):
            self.inv.cadastrar_ativo(criar_equipamento(TipoAtivo.NOTEBOOK, 1, "novo", "Xavier", "Sala 1"))
        with self.assertRaises(ErroInventario):
            self.inv.cadastrar_ativo(criar_equipamento(TipoAtivo.NOTEBOOK, 9, "srv-01", "Xavier", "Sala 1"))

    def test_soma_da_linha_deve_ser_menor_que_um(self):
        self.inv.cadastrar_dependencia(2, 1, 0.6)
        with self.assertRaises(ErroInventario):
            self.inv.cadastrar_dependencia(3, 1, 0.4)  # 0,6 + 0,4 = 1
        self.inv.cadastrar_dependencia(2, 1, 0.3)      # atualizar a mesma não soma duas vezes
        self.inv.cadastrar_dependencia(3, 1, 0.4)

    def test_remover_ativo_remove_dependencias(self):
        self.inv.cadastrar_dependencia(2, 1, 0.4)
        self.inv.cadastrar_dependencia(1, 3, 0.5)
        self.inv.remover_ativo(1)
        self.assertEqual(self.inv.dependencias, [])
        recarregado = Inventario(self.pasta.name)
        self.assertEqual(len(recarregado.ativos), 2)
        self.assertEqual(recarregado.avisos, [])

    def test_arquivo_corrompido_vira_backup(self):
        caminho = os.path.join(self.pasta.name, "inventario_ativos.json")
        with open(caminho, "w", encoding="utf-8") as f:
            f.write("{ isso nao e json")
        recarregado = Inventario(self.pasta.name)
        self.assertEqual(recarregado.ativos, [])
        self.assertTrue(any("corrompido" in nome for nome in os.listdir(self.pasta.name)))


if __name__ == "__main__":
    unittest.main()
