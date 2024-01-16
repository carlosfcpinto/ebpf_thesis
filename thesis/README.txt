Modelo para a escrita em LaTeX de teses NÃO OFICIAL da Universidade da Beira Interior, seguindo o despacho Reitoral nº 49/R/2010. 
Revogado pelo despacho Reitoral nº 2019/R/630

Versão 3.0 - 2020/01/31
	Esta Versão é um update à versão oficial Versão 2.2 .
	Esta é uma Versão NÃO OFICIAL do modelo de Teses da UBI. Segue o despacho Reitoral nº 2019/R/630 quase na integra. Sem garantias algumas. 
	Aguns erros que a UBI forneceu no ficheiro WORD foram corrigidos no LaTeX.  


Versão 2.2 - 2016/06/01

Em relação à Versão 2.1 na Versão 2.2 existem duas opções para as Listas, Lista de Figuras e Lista de Tabelas, podem aparecer as palavras "Figura" e "Tabela" nas respectivas listas. Como exemplo:
	2.1 Correspondência entre as cores das riscas das resistências e o seu valor óhmico. .3
	ou
	Tabela 2.1 Correspondência entre as cores das riscas das resistências e o seu valoróhmico. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
3

Em relação à Versão 2.0 na Versão 2.1 passa-se a deixar de compilar em PDFLaTeX para se passar a compilar em XeLaTeX.
É necessa?io passar a compilar em XeLaTeX para utilizar o tipo de letra Trebuchet.

Para utilizar o XeLaTeX a codificação dos ficheiros tem que ser em UTF-8.

Utilizadores de Linux com gestor de pacotes DEB têm que ter o pacote "ttf-mscorefonts-installer" instalado
para utilizar o tipo de letra Georgia. Não foram testados outros gestores de pacotes.

O modelo foi compilado em XeLaTeX e sem erros num sistema Debian 10 Gnome 64-bit 64-bit (Não foram testadas outras distribuições), 
com Texmaker 5.0.3 e com texlive-full. Incluídos no .zip:

- Tese.tex, o ficheiro principal do documento;
- PaginaRosto.tex, que gera a página de rosto;
- Intro.tex e Exemplos.tex, exemplos de capítulos com tabela, figura e referências;
- formatacaoUBI.tex e estiloUBI.sty, definem a formatação da tese, não é recomendável 
editar estes ficheiros;
- estilo-biblio.bst, define o estilo da bibliografia, pode ser trocado por qualquer 
outro ficheiro de acordo com a norma a utilizar (deixada em aberto pelo despacho);
- bibliografia.bib, onde se inserem as referências da tese em formato bibTeX;
- directório imagens, onde por defeito deverão ser colocadas as imagens a utilizar.



