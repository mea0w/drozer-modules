# drozer-modules

I wrote some useless drozer-modules...

## Usage notes

* Create repository

    dz> module repository create [/absolute_path/repositories]

or change .drozer_config file  (C:\Users\root\\.drozer_config)

    [repositories]  
    C|\Temp\modules  =  C:\Temp\modules

* Copy all files in 'modules' folder into 'repository' Folder

* Module install

    dz> module install vuln.attack.components

## Run modules

* vuln.attack.findleak

Match leakage in .apk file(support Url,IP,ID cards,phone,emails)

    dz> run vuln.attack.findleak -a com.android.chrome

* vuln.attack.components

Test all components(Maybe some bugs)

    dz> run vuln.attack.components -a com.android.chrome

* More useful modules

https://github.com/FSecureLABS/drozer-modules
