import re
from pydiesel.reflection import ReflectionException
from drozer.modules import common, Module
 
class findips(Module, common.FileSystem, common.PackageManager, common.Provider, common.Strings, common.ZipFile):
 
    name = "Find IPs specified in packages."
    description = """
    Find IPs in apk files
    """
    examples = ""
    author = "7h0r@ms509"
    date = "2015-12-9"
    license = ""
    path = ["vuln", "attack"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]
 
    def add_arguments(self, parser):
        parser.add_argument("-a", "--package", help="specify a package to search")
 
    def execute(self, arguments):
        self.ip_matcher = re.compile(r"((?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d))))")
        if arguments.package != None:
            self.check_package(arguments.package, arguments)
        else:
            for package in self.packageManager().getPackages(common.PackageManager.GET_PERMISSIONS):
                try:
                    self.check_package(package.packageName, arguments)
                except Exception, e:
                    print str(e)
 
    def check_package(self, package, arguments):
        self.deleteFile("/".join([self.cacheDir(), "classes.dex"]))
        ips = []
 
        for path in self.packageManager().getSourcePaths(package):
            strings = []
            if ".apk" in path:
                dex_file = self.extractFromZip("classes.dex", path, self.cacheDir())
                if dex_file != None:
                    strings = self.getStrings(dex_file.getAbsolutePath())
 
                    dex_file.delete()
                    strings += self.getStrings(path.replace(".apk", ".odex"))
            elif (".odex" in path):
                strings = self.getStrings(path)
            else:
                continue
 
            for s in strings:
                m = self.ip_matcher.search(s)
                if m is not None:
                    ips.append(s)
 
            if len(ips) > 0:
                self.stdout.write("%s\n" % str(package))
 
            for ip in ips:
                    self.stdout.write("  %s\n" % ip)
 
            if len(ips) > 0 :
                self.stdout.write("\n")