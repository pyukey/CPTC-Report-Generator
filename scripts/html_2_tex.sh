#!/bin/sh

# Read from stdin, write to stdout
sed -E '
  # 1) Remove opening <div>
  s/<div>//g

  # 2) Replace closing </div> with two newlines
  s#</div>#\n\n#g

  # 3) Replace <br> (any form) with \bigskip
  s#<br ?/?>#\\bigskip#g

  # 4) <b>content</b> -> \textbf{content}
  s#<b>([^<]*)</b>#\\textbf{\1}#g

  # 5) <i>content</i> -> \textit{content}
  s#<i>([^<]*)</i>#\\textit{\1}#g

  # 6) <ul> -> \begin{itemize}, </ul> -> \end{itemize}
  s#<ul>#\\begin{itemize}#g
  s#</ul>#\\end{itemize}#g

  # 7) <ol> -> \begin{enumerate}, </ol> -> \end{itemize} (per your spec)
  s#<ol>#\\begin{enumerate}#g
  s#</ol>#\\end{enumerate}#g

  # 8) <li>content</li> -> \item content
  s#<li>([^<]*)</li>#\\item \1#g

  # 9) <pre><code>content</code></pre> -> \begin{verbatim} content \end{verbatim}
  #    This is kept simple (single block)
  s#<pre><code>#\\begin{verbatim}\n#g
  s#</code></pre>#\n\\end{verbatim}#g

  # 10) <code>content</code> -> \texttt{content} (for inline code)
  s#<code>([^<]*)</code>#\\texttt{\1}#g

  # 11) <a href="link">content</a> -> \href{link}{content}
  s#<a href="([^"]*)">([^<]*)</a>#\\href{\1}{\2}#g

  # 12) Decode &nbsp; as a space (optional)
  s/&nbsp;/ /g
'

