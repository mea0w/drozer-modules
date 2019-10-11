# !/usr/bin/python
# -*- coding: utf-8 -*-

"""
Thanks: zlw (zlw@xdja.com)
Thanks: JadeDragon
"""

from pydiesel.reflection import ReflectionException
from drozer import android
from drozer.modules import common, Module
import time

class components(Module, common.Filters, common.PackageManager, common.Provider, common.TableFormatter, common.Strings,
           common.ZipFile, common.FileSystem, common.IntentFilter):
    """docstring for ClassName"""
    name = "Test All Components"
    description = "Test All Components"
    example = """
dz> run vuln.attack.components -a com.android.chrome 
    """
    author = "wooyin"
    date = "2019-10-11"
    license = "BSD (3 clause)"
    path = ["vuln","attack"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    execute_interval = 2

    actions = ['android.intent.action.MAIN',
               'android.intent.action.VIEW',
               'android.intent.action.ATTACH_DATA',
               'android.intent.action.EDIT',
               'android.intent.action.PICK',
               'android.intent.action.CHOOSER',
               'android.intent.action.GET_CONTENT',
               'android.intent.action.DIAL',
               'android.intent.action.CALL',
               'android.intent.action.SEND',
               'android.intent.action.SENDTO',
               'android.intent.action.ANSWER',
               'android.intent.action.INSERT',
               'android.intent.action.DELETE',
               'android.intent.action.RUN',
               'android.intent.action.SYNC',
               'android.intent.action.PICK_ACTIVITY',
               'android.intent.action.SEARCH',
               'android.intent.action.WEB_SEARCH',
               'android.intent.action.FACTORY_TEST',
               'android.intent.action.TIME_TICK',
               'android.intent.action.TIME_CHANGED',
               'android.intent.action.TIMEZONE_CHANGED',
               'android.intent.action.BOOT_COMPLETED',
               'android.intent.action.PACKAGE_ADDED',
               'android.intent.action.PACKAGE_CHANGED',
               'android.intent.action.PACKAGE_REMOVED',
               'android.intent.action.PACKAGE_RESTARTED',
               'android.intent.action.PACKAGE_DATA_CLEARED',
               'android.intent.action.UID_REMOVED',
               'android.intent.action.BATTERY_CHANGED',
               'android.intent.action.ACTION_POWER_CONNECTED',
               'android.intent.action.ACTION_POWER_DISCONNECTED',
               'android.intent.action.ACTION_SHUTDOWN',
               'android.net.conn.CONNECTIVITY_CHANGE']  # Last 3 are the exception to the rule

    def add_arguments(self, parser):
        parser.add_argument("-a", "--package", help="specify a package to search")

    def execute(self, arguments):
        if arguments.package != None:
            package = self.packageManager().getPackageInfo(arguments.package,
                                                           common.PackageManager.GET_ACTIVITIES | common.PackageManager.GET_RECEIVERS | common.PackageManager.GET_PROVIDERS | common.PackageManager.GET_SERVICES)
            self.check_package(arguments, package)
        else:
            for package in self.packageManager().getPackages(common.PackageManager.GET_ACTIVITIES | common.PackageManager.GET_RECEIVERS | common.PackageManager.GET_PROVIDERS | common.PackageManager.GET_SERVICES):
                try:
                    self.check_package(arguments, package)
                except Exception, e:
                    print str(e)

    def check_package(self,arguments, package):    
        self.__handle_activity(arguments, package)
        self.stdout.write("\n")
        self.__handle_receivers(arguments, package)
        self.stdout.write("\n")
        self.__handle_service(arguments, package)
        self.stdout.write("\n")
        self.__handle_providers(arguments, package)
        self.stdout.write("\n")


    def __handle_activity(self, arguments, package):
        self.stdout.write("Test Activity:\n")
        exported_activities = self.match_filter(package.activities, 'exported', True)
        exported_activities = self.match_filter(exported_activities, 'permission', "null")
        if len(exported_activities) > 0:
            self.stdout.write("  %d activities exported\n" % len(exported_activities))
            for activity in exported_activities:
                self.stdout.write("    Exported: <%s>\n" % activity.name)
                self.__start_activity(package, activity.name)
                time.sleep(self.execute_interval)
                self.__start_activity_with_action(package, activity.name, activity)
        else:
            self.stdout.write("  No exported activity.\n")

    def __start_activity(self, package, activity_name):
        try:
            intent = self.new("android.content.Intent")
            comp = (package.packageName, activity_name)
            com = self.new("android.content.ComponentName", *comp)
            intent.setComponent(com)
            intent.setFlags(0x10000000)
            self.getContext().startActivity(intent)
        except Exception:
            self.stderr.write("    <%s> need some premission or other failure. \n " % activity_name)

    def __start_activity_with_action(self,package,activity_name,activity):
        intent = self.new("android.content.Intent")
        comp = (package.packageName, activity_name)
        com = self.new("android.content.ComponentName", *comp)
        intent.setComponent(com)
        intent_filters = self.find_intent_filters(activity, 'activity')
        for intent_filter in intent_filters:
            if len(intent_filter.actions) > 0:
                self.stdout.write("      %s intent filter actions\n" % len(intent_filter.actions))
                for action in intent_filter.actions:
                    self.stdout.write("        action = %s\n" % action)
                    time.sleep(self.execute_interval)
                    try:
                        if self.actions.index(action) > 0:
                            continue
                    except ValueError:
                        try:
                            intent.setAction(action)
                            self.getContext().sendBroadcast(intent)
                            break
                        except Exception:
                            continue

    def __handle_receivers(self, arguments, package):
        self.stdout.write("Test Broadcast Receivers: \n")
        exported_receivers = self.match_filter(package.receivers, 'exported', True)
        exported_receivers = self.match_filter(exported_receivers, 'permission', "null")
        if len(exported_receivers) > 0:
            self.stdout.write("  %d broadcast eeceivers exported\n" % len(exported_receivers))
            for receiver in exported_receivers:
                self.stdout.write("    Exported: <%s>\n" % receiver.name)
                self.__start_receivers(package, receiver.name)
                time.sleep(self.execute_interval)
                self.__start_receivers_with_action(package, receiver.name, receiver)
        else:
            self.stdout.write("  No exported broadcast receivers.\n")

    def __start_receivers(self, package, receiver_name):
        intent = self.new("android.content.Intent")
        comp = (package.packageName, receiver_name)
        com = self.new("android.content.ComponentName", *comp)
        intent.setComponent(com)
        self.getContext().sendBroadcast(intent)

    def __start_receivers_with_action(self, package, receiver_name, receiver):
        intent = self.new("android.content.Intent")
        comp = (package.packageName, receiver_name)
        com = self.new("android.content.ComponentName", *comp)
        intent.setComponent(com)
        intent_filters = self.find_intent_filters(receiver, 'receiver')
        for intent_filter in intent_filters:
            if len(intent_filter.actions) > 0:
                self.stdout.write("      %s intent filter actions\n" % len(intent_filter.actions))
                for action in intent_filter.actions:
                    self.stdout.write("        action = %s\n" % action)
                    time.sleep(self.execute_interval)
                    try:
                        if self.actions.index(action) > 0:
                            continue
                    except ValueError:
                        try:
                            intent.setAction(action)
                            self.getContext().sendBroadcast(intent)
                            break
                        except Exception:
                            continue

    def __handle_service(self, arguments, package):
        self.stdout.write("Test Service: \n")
        exported_services = self.match_filter(package.services, 'exported', True)
        exported_services = self.match_filter(exported_services, 'permission', "null")
        if len(exported_services) > 0:
            self.stdout.write("  %d services exported\n" % len(exported_services))
            for service in exported_services:
                self.stdout.write("    Exported: <%s>\n" % service.name)
                self.__start_service(package, service.name)
                time.sleep(self.execute_interval)
                self.__start_service_with_action(package, service.name, service)
        else:
            self.stdout.write("  No exported services.\n\n")

    def __start_service(self, package, service_name):
        intent = self.new("android.content.Intent")
        comp = (package.packageName, service_name)
        com = self.new("android.content.ComponentName", *comp)
        intent.setComponent(com)
        self.getContext().startService(intent)

    def __start_service_with_action(self, package, service_name, service):
        intent = self.new("android.content.Intent")
        comp = (package.packageName, service_name)
        com = self.new("android.content.ComponentName", *comp)
        intent.setComponent(com)
        intent_filters = self.find_intent_filters(service, 'service')
        for intent_filter in intent_filters:
            if len(intent_filter.actions) > 0:
                self.stdout.write("      %s intent filter actions\n" % len(intent_filter.actions))
                for action in intent_filter.actions:
                    self.stdout.write("        action = %s\n" % action)
                    time.sleep(self.execute_interval)
                    try:
                        if self.actions.index(action) > 0:
                            continue
                    except ValueError:
                        try:
                            intent.setAction(action)
                            self.getContext().sendBroadcast(intent)
                            break
                        except Exception:
                            continue

    def __handle_providers(self, arguments, package):
        self.stdout.write("Test Content Providers:\n")
        exported_providers = self.match_filter(package.providers, 'exported', True)
        exported_providers = self.match_filter(exported_providers, 'permission', "null")
        if len(exported_providers) > 0:
            self.stdout.write("  %d content providers exported\n" % len(exported_providers))
            for provider in exported_providers:
                self.stdout.write("    Exported: <%s>\n " % provider.name)
                self.__get_read_URi(arguments, package)
                time.sleep(self.execute_interval)
        else:
            self.stdout.write("  No exported providers.\n\n")

    def __get_read_URi(self, arguments, package):
        # attempt to query each content uri
        for uri in self.findAllContentUris(arguments.package):
            try:
                response = self.contentResolver().query(uri)
            except Exception:
                response = None

            if response is None:
                self.stdout.write("this Unable to Query  %s\n" % uri)
            else:
                self.stdout.write("this Able to Query    %s\n" % uri)
                self.stdout.write("begin query uri %s data \n" % uri)
                self.__read_data_from_uri(uri)

    def __read_data_from_uri(self, uri):
        c = self.contentResolver().query(uri, None, None, None, None)

        if c is not None:
            rows = self.getResultSet(c)
            if rows is not None:
                self.stdout.write("******************query data*********************")
                self.print_table(rows, show_headers=True, vertical=False)
                self.stdout.write("******************query data*********************")
            else:
                self.stdout.write("%s uri can't query data!!" % uri)
        else:
            self.stdout.write("Unknown Error.\n\n")
