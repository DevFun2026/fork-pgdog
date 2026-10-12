"""Finalize a draft only after its exact approval is present on GitHub."""
import copy
import hashlib
import json
import os
from pathlib import Path

from artifacts.owner_approval import github_api
from artifacts.owner_release import approval_body, parse_owner_receipt, validate_live
from artifacts.release_receipt import canonical, unique_object


def _run_path(root, value, lexical_root):
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    relative = None
    for candidate in (root, lexical_root):
        try:
            relative = path.relative_to(candidate / '.agent/.runs')
            break
        except ValueError:
            pass
    if relative is None:
        raise ValueError('Receipt paths must be inside the local run directory') from None
    if '..' in relative.parts:
        raise ValueError('Unsafe receipt path')
    path = root / '.agent/.runs' / relative
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('Receipt path contains a symlink')
    return path


def finalize_receipt(root, draft, output, comment_id, *, api=None):
    lexical_root = Path(root).absolute()
    root = lexical_root.resolve(strict=True)
    draft = _run_path(root, draft, lexical_root)
    output = _run_path(root, output, lexical_root)
    if type(comment_id) is not int or comment_id <= 0:
        raise ValueError('A positive owner approval comment ID is required')
    if not draft.is_file() or output.exists() or output.is_symlink():
        raise ValueError('Draft must be regular and final receipt must not exist')
    with draft.open('rb') as stream:
        raw = stream.read(32769)
    if len(raw) > 32768:
        raise ValueError('Receipt exceeds 32 KiB')
    try:
        payload = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeDecodeError):
        raise ValueError('Malformed receipt draft') from None
    if not isinstance(payload, dict):
        raise ValueError('Receipt draft must be an object')  # noqa: TRY004 -- malformed receipt fails validation
    parse_owner_receipt(payload, payload.get('source_sha'), allow_unapproved=True)
    if payload['authorization']['comment_id'] != 0:
        raise ValueError('Receipt was already finalized')
    receipt = copy.deepcopy(payload)
    receipt['authorization']['comment_id'] = comment_id
    receipt['authorization']['comment_body_sha256'] = hashlib.sha256(
        approval_body(receipt).encode('utf-8')).hexdigest()
    parse_owner_receipt(receipt, receipt['source_sha'])
    api = api or github_api
    user = api('user')
    if not isinstance(user, dict) or type(user.get('id')) is not int:
        raise ValueError('Authenticated dispatch identity is unavailable')
    validate_live(receipt, actor_id=str(user['id']), workflow_sha=receipt['workflow_sha'],
                  root=root, api=api)
    if draft.read_bytes() != raw:
        raise ValueError('Draft changed during owner approval validation')
    final = canonical(receipt)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(final + b'\n')
    return hashlib.sha256(final).hexdigest()
