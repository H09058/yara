import yara
rules = yara.compile(sources={
'identifier_for_instance_of rule':'rule BadBoy { 
                       'strings': [('$a', ''),('$b', '') , ('$c', 'http://bar.com/badfile2.exe')],
                       'condition': '$a and ($b or 
