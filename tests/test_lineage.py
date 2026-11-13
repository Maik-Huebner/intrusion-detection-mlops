from ids.lineage import data_versions, flatten

LOCK = """\
schema: '2.0'
stages:
  prepare:
    cmd: python -m ids.pipeline.prepare
    deps:
    - path: data/raw/CICIDS2017_improved.zip
      md5: aaa111
    - path: src/ids/pipeline/prepare.py
      md5: bbb222
  split:
    cmd: python -m ids.pipeline.split
    outs:
    - path: data/prepared
      md5: ccc333.dir
"""


def test_flatten_nested_dicts_and_lists():
    data = {"split": {"train_days": ["monday", "tuesday"], "test_size": 0.2}, "f1": 0.9}
    assert flatten(data) == {"split.train_days": "monday,tuesday", "split.test_size": 0.2, "f1": 0.9}


def test_data_versions_reads_dvc_lock(tmp_path):
    lock = tmp_path / "dvc.lock"
    lock.write_text(LOCK, encoding="utf-8")
    assert data_versions(lock) == {"data.raw_md5": "aaa111", "data.prepared_md5": "ccc333.dir"}
