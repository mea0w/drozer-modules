import re
from pydiesel.reflection import ReflectionException
from drozer.modules import common, Module
 
class findleak(Module, common.FileSystem, common.PackageManager, common.Provider, common.Strings, common.ZipFile):
 
    name = "findleak"
    description = """
    Find leak information in .apk file
    """
    examples = "dz> run vuln.attack.findleak -a com.aculearn.jst"
    author = "wooyin(https://github.com/wooyin)"
    date = "2019-10-14"
    license = ""
    path = ["vuln", "attack"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]
 
    def add_arguments(self, parser):
        parser.add_argument("-a", "--package", help="specify a package to search")
 
    def execute(self, arguments):
        if arguments.package != None:
            self.check_package(arguments.package, arguments)
        else:
            for package in self.packageManager().getPackages(common.PackageManager.GET_PERMISSIONS):
                try:
                    self.check_package(package.packageName, arguments)
                except Exception, e:
                    print str(e)

    def check_package(self, package, arguments):
        # Find IPs leakage
        self.stdout.write("===Find IPs===\n")
        self.leak_matcher = re.compile(r"(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)")
        self.find_leak_with_re(package, arguments)

        # Find Urls leakage
        self.stdout.write("===Find Urls===\n")
        self.leak_matcher = re.compile("(https|http|ftp|rtsp|mms)?://[^\s]+")
        self.find_leak_with_re(package, arguments)

        # Find Emails leakage
        self.stdout.write("===Find Emails===\n")
        self.leak_matcher = re.compile(r"\w[-\w.+]*@([A-Za-z0-9][-A-Za-z0-9]+\.)+[A-Za-z]{2,14}")
        self.find_leak_with_re(package, arguments)        

        # Find Tels leakage
        self.stdout.write("===Find Tels===\n")
        self.leak_matcher = re.compile(r"0?(13|14|15|17|18|19)[0-9]{9}")
        self.find_leak_with_re(package, arguments)

        # Find ID cards leakage
        self.stdout.write("===Find ID cards===\n")
        self.leak_matcher = re.compile(r'(^[1-9]\d{5}(18|19|([23]\d))\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$)|(^[1-9]\d{5}\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{2}[0-9Xx]$)')
        self.find_leak_with_re(package, arguments)
 
    def find_leak_with_re(self, package, arguments):
        self.deleteFile("/".join([self.cacheDir(), "classes.dex"]))
        leaks = []
 
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
                m = self.leak_matcher.search(s)
                if m is not None:
                    leaks.append(s)
 
            if len(leaks) > 0:
                self.stdout.write("<Package: %s>\n" % str(package))
 
            for leak in leaks:
                self.stdout.write("%s\n" % leak)
 
            self.stdout.write("\n")