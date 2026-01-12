UPDATE "system"
SET "value" = 'true'
WHERE "key" = 'is_setup_complete';


INSERT INTO "users" ("username",
                     "password",
                     "salt",
                     "name",
                     "email",
                     "external",
                     "active",
                     "roles",
                     "changetimestamp")
SELECT 'admin',
       'SHA=7f062dc2ef82d2b87f012fc17d70c372aa4e2883d9b6c5c1cc7382a5c868b724',
       'eWAbKQmxNP',
       'admin',
       'admin@organisation.com',
       FALSE,
       '1',
       '{admin,cf_remoteagent}',
       now() ON CONFLICT (username,
                          EXTERNAL) DO
UPDATE
SET password = 'SHA=7f062dc2ef82d2b87f012fc17d70c372aa4e2883d9b6c5c1cc7382a5c868b724',
    salt = 'eWAbKQmxNP';
