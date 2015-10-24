#!/usr/bin/perl

if (@ARGV != 1) {
    print "usage: \$./ksym_disasm.pl symbol_name\n";
    exit(1);
}

open(IN, "less /proc/kallsyms |");
@str = <IN>;
close(IN);

$find_begin = 0;
foreach $str_line (@str) {
    my @str_line_split = split(/\s+/, $str_line);
    @str_line_split[2] =~ s/\x0D?\x0A?$//;
    if (@str_line_split[2] eq "@ARGV[0]") {
        $addr = @str_line_split[0];
        last;
    }
}
system "./kdisasm $addr";

