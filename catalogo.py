class VulnerabilidadeConhecida:
    def __init__(self, nome, nome_pt, categoria, severidade, cvss):
        self.nome = nome
        self.nome_pt = nome_pt
        self.categoria = categoria
        self.severidade = severidade
        self.cvss = cvss
# Teste rápido
sql = VulnerabilidadeConhecida("SQL Injection", "Injeção de SQL", "Injeção de Código", "Crítica", 9.8)
print(sql.nome)
print(sql.cvss)