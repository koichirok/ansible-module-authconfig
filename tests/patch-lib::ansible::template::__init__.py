--- ansible/template/__init__.py.bak	2016-11-01 12:43:19.000000000 +0900
+++ ansible/template/__init__.py	2016-11-29 19:52:35.239201986 +0900
@@ -355,10 +355,12 @@
                 # we don't use iteritems() here to avoid problems if the underlying dict
                 # changes sizes due to the templating, which can happen with hostvars
                 for k in variable.keys():
-                    if k not in static_vars:
-                        d[k] = self.template(variable[k], preserve_trailing_newlines=preserve_trailing_newlines, fail_on_undefined=fail_on_undefined, overrides=overrides)
+                    key = self.template(k, preserve_trailing_newlines=preserve_trailing_newlines, fail_on_undefined=fail_on_undefined, overrides=overrides)
+
+                    if key not in static_vars:
+                        d[key] = self.template(variable[k], preserve_trailing_newlines=preserve_trailing_newlines, fail_on_undefined=fail_on_undefined, overrides=overrides)
                     else:
-                        d[k] = variable[k]
+                        d[key] = variable[k]
                 return d
             else:
                 return variable
