"""Synthetic DECON retire guard utility tests."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_decon_retire_guard as mod

class DeconRetireGuardTests(unittest.TestCase):
    def test_extract(self):
        self.assertEqual(mod.extract("int foo(void)\n{\n return 0;\n}\n","int foo("),
                         "int foo(void)\n{\n return 0;\n}\n")

    def test_missing_signature(self):
        with self.assertRaises(ValueError):
            mod.extract("bad","static int decon_get_valid_fd(")

    def test_host_fixture_compiles_in_strict_c11(self):
        # Minimal independent functions exercise all fixture stubs. The
        # integration job separately compiles the actual pinned source.
        source = r'''
static int decon_get_valid_fd(void)
{
    int fd = get_unused_fd_flags(O_CLOEXEC);
    return fd;
}
void decon_cancel_release_fences(struct decon_device *d, struct decon_win_config_data *w)
{
    for(int i=0;i<d->dt.max_win;i++) {
        if(w->config[i].rel_fence>=0)put_unused_fd(w->config[i].rel_fence);
        w->config[i].rel_fence=-1;
    }
}
int decon_reserve_release_fences(struct decon_device *d, struct decon_win_config_data *w)
{
    int fd=decon_get_valid_fd();
    decon_cancel_release_fences(d,w);
    return fd;
}
int decon_create_fence(struct decon_device *d,struct sync_file **out)
{
    struct dma_fence *f=kzalloc(sizeof(*f),GFP_KERNEL);
    if(!f)return -ENOMEM;
    dma_fence_init(f,&decon_fence_ops,&d->fence.lock,d->fence.context,
                   atomic_inc_return(&d->fence.timeline));
    *out=sync_file_create(f);
    dma_fence_put(f);
    if(!*out)return -ENOMEM;
    int fd=decon_get_valid_fd();
    if(fd<0){fput((*out)->file);*out=NULL;return fd;}
    struct dpu_fence_info i;
    dpu_save_fence_info(fd,f,&i);
    return fd;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            mod.compile_fixture(source,root/"test.c",root/"test")
            self.assertTrue((root/"test").is_file())
