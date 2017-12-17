#!/bin/sh


echo "=====PGdumper current code====="
echo ''
echo "Work still in progress"
echo ''
for n in *.pl */*.ep;do 
    echo '===='$n'===='
    echo ''
    echo '<code perl '$n'>'
    cat $n
    echo '</code>'
    echo ''
done
echo '----'
echo '[<>]'

#EOF

