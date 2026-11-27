/* Offline libsepol context validity check; does not load any kernel policy. */
#include <stdio.h>
#include <sepol/context.h>
#include <sepol/policydb.h>
#include <sepol/handle.h>

int main(int argc, char **argv)
{
    int rc = 2;
    FILE *fp = NULL;
    sepol_handle_t *h = NULL;
    sepol_policydb_t *db = NULL;
    sepol_policy_file_t *pf = NULL;
    if (argc < 3 || argc > 514)
        return 2;
    h = sepol_handle_create();
    if (!h || sepol_policydb_create(&db) < 0 ||
        sepol_policy_file_create(&pf) < 0)
        goto done;
    fp = fopen(argv[1], "rb");
    if (!fp)
        goto done;
    sepol_policy_file_set_fp(pf, fp);
    if (sepol_policydb_read(db, pf) < 0)
        goto done;
    rc = 0;
    for (int i = 2; i < argc; ++i) {
        sepol_context_t *ctx = NULL;
        int valid = sepol_context_from_string(h, argv[i], &ctx) == 0 &&
                    sepol_context_check(h, db, ctx) == 0;
        sepol_context_free(ctx);
        if (!valid)
            rc = 1;
        printf("%d %s\n", i - 2, valid ? "VALID" : "INVALID");
    }
done:
    if (pf) sepol_policy_file_free(pf);
    if (db) sepol_policydb_free(db);
    if (fp) fclose(fp);
    if (h) sepol_handle_destroy(h);
    return rc;
}
