diff --git a/lib/ansible/template/__init__.py b/lib/ansible/template/__init__.py
index 7e0c559..f9ee02f 100644
--- ansible/template/__init__.py
+++ ansible/template/__init__.py
@@ -418,16 +418,24 @@ class Templar:
                 # we don't use iteritems() here to avoid problems if the underlying dict
                 # changes sizes due to the templating, which can happen with hostvars
                 for k in variable.keys():
+                    k_orig = k
+                    k = self.template(
+                            k,
+                            preserve_trailing_newlines=preserve_trailing_newlines,
+                            fail_on_undefined=fail_on_undefined,
+                            overrides=overrides,
+                            disable_lookups=disable_lookups,
+                        )
                     if k not in static_vars:
                         d[k] = self.template(
-                                   variable[k],
+                                   variable[k_orig],
                                    preserve_trailing_newlines=preserve_trailing_newlines,
                                    fail_on_undefined=fail_on_undefined,
                                    overrides=overrides,
                                    disable_lookups=disable_lookups,
                                )
                     else:
-                        d[k] = variable[k]
+                        d[k] = variable[k_orig]
                 return d
             else:
                 return variable
