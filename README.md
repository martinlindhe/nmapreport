Produces a report of a nmap scan
    + recon


# USAGE

Scan some nmap targets and produce an xml report:

    $ nmap -sV -A -oX report.xml 192.168.44.0/24

    $ go run github.com/martinlindhe/nmapreport@latest report.xml
