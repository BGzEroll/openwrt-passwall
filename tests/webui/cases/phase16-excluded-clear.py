def clear_excluded():
 go('other');flag('sniffing_override_dest',True);field('excluded_domains','textarea').fill('ui-clear.example\n');submit()
 assert ssh('cat /usr/share/passwall/rules/domains_excluded')=='ui-clear.example'
 go('other');field('excluded_domains','textarea').fill('');submit()
 assert ssh('cat /usr/share/passwall/rules/domains_excluded')=='','GUI clear did not clear excluded_domains file'
check('GUI can clear all sniffing-excluded domains',clear_excluded)
