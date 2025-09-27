# CPTC-Report-Generator
A collaborative, rich text editor that automatically converts findings to this template: https://github.com/ufsit/CPTC-Report

## Setup

After cloning the repo, simply run `python3 collab.py`. Now you can visit `localhost:8000` in your web browser to interact with the tool.

## Features

Here are the currently supported features:

- **Findings** are listed at the very top. Clicking on one of them will load its details for you to modify.
- **Templates** are listed underneath the findings. Clicking on one of them will automatically generate and load a new finding.
- Each section supports a **rich text editor**. Some of the features support **keyboard shortcuts** (Ctrl+b, Ctrl+i), while for the others you need to highlight your target text and then press the corresponding button:
   - Bold (B) 
   - Italics (I)
   - Code blocks (C)
   - Bulleted list (- List)
   - Numbered list (1. List)
- This tool supports **concurrent editing** to some extent. Each section of each finding can be edited. The **Edit** button can be pressed to switch into edit mode for that section.   
When it is edited by one person, that section becomes *Locked*, which means others can still view that section, but editing is disabled for them. When the editor switches back to **View** mode, the changes are saved and the lock is removed.
- This tool automatically **converts between LaTeX and HTML**. The data is stored as LaTeX files on the server, but are rendered on the webpage.

## Explanation

This section explains a few important aspects about how the tool works, so it easier for others to modify.


## Prewrites

All prewrites are stored in the `templates\` directory. To contribute a prewrite, **create a new folder** in `templates\` for the prewrite and include the following files:

- `name.tex` - contains the name of the vulnerability.
- `details.tex` - explains how the vulnerability works.
- `confirmation.tex` - includes the steps to verify the vulnerability exists and can be exploited.
- `impact.tex` - describes the impact of the finding.
- `mitigations.tex` - describes how to patch the vulnerability.
- `references.tex` - includes links to sites that explain the vulnerability in more detail. 

## TODO

- Add a command to concatenate all the LaTeX files together into a full report
- Add more prewrites