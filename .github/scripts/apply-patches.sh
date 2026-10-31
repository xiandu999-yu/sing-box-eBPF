#!/usr/bin/env bash
#
# 给 sing-box 源码和它依赖的 Go 模块打补丁。
#
#   patches/sing-box/*.patch         -> 打在 src/（sing-box 本体）
#   patches/*.patch                  -> 同上（旧的扁平放法，仍然支持）
#   patches/modules/<name>/*.patch   -> 打在依赖模块上
#
# 模块目录结构：
#   patches/modules/sing-ebpf/
#   ├── pin.env                      # 可选；没有就回退到 go.mod 的版本
#   │     MODULE_PATH=github.com/CHIZI-0618/sing-ebpf
#   │     MODULE_REPO=https://github.com/CHIZI-0618/sing-ebpf   # 可省，默认同 MODULE_PATH
#   │     MODULE_REF=main            # 分支 / tag / commit（完整或缩写都行）
#   └── 0001-xxx.patch
#
# 直接克隆模块仓库再替换（go mod edit -replace），所以不依赖 go.mod 里的
# 版本是不是伪版本：pin.env 写了 REF 就按 REF 拉，没写才去 go.mod 里找
# 伪版本里的 commit。
#
# 用法：apply-patches.sh [src-dir]

set -euo pipefail
shopt -s nullglob

SRC="${1:-src}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC_ABS="$ROOT/$SRC"

[ -d "$SRC_ABS" ] || { echo "::error::source directory not found: $SRC_ABS"; exit 1; }

apply_patches() {
	local target="$1" label="$2"
	shift 2
	local files=("$@")
	[ ${#files[@]} -gt 0 ] || return 0
	for file in "${files[@]}"; do
		echo "::group::apply ${file#"$ROOT/"} -> ${label}"
		git -C "$target" apply --3way --whitespace=nowarn "$file"
		echo "::endgroup::"
	done
}

# ---- sing-box 本体 ---------------------------------------------------------
apply_patches "$SRC_ABS" "sing-box" "$ROOT"/patches/sing-box/*.patch
apply_patches "$SRC_ABS" "sing-box" "$ROOT"/patches/*.patch

# ---- 依赖模块 --------------------------------------------------------------
# 没有 pin.env 时的回退：从 go.mod 找 <name> 对应的
# "模块路径 仓库 版本"（replace 优先于 require），版本取自伪版本。
lookup_module() {
	local name="$1" line old repo ver
	local gomod="$SRC_ABS/go.mod"

	while IFS= read -r line; do
		[ -n "$line" ] || continue
		old="$(awk '{print $2}' <<<"$line")"
		repo="$(awk '{print $4}' <<<"$line")"
		ver="$(awk '{print $5}' <<<"$line")"
		if [ "$(basename "$repo")" = "$name" ]; then
			printf '%s\t%s\t%s\n' "$old" "$repo" "$ver"
			return 0
		fi
	done < <(grep -E '^replace[[:space:]]+[^[:space:]]+[[:space:]]+=>[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+$' "$gomod" || true)

	while IFS= read -r line; do
		[ -n "$line" ] || continue
		old="$(awk '{print $1}' <<<"$line")"
		ver="$(awk '{print $2}' <<<"$line")"
		if [ "$(basename "$old")" = "$name" ]; then
			printf '%s\t%s\t%s\n' "$old" "$old" "$ver"
			return 0
		fi
	done < <(grep -E '^[[:space:]]*[A-Za-z0-9._-]+(\.[A-Za-z0-9._-]+)+/[^[:space:]]+[[:space:]]+v[0-9]' "$gomod" || true)

	return 1
}

if [ -d "$ROOT/patches/modules" ]; then
	for dir in "$ROOT"/patches/modules/*/; do
		name="$(basename "$dir")"
		files=("$dir"*.patch)
		if [ ${#files[@]} -eq 0 ]; then
			echo "::notice::patches/modules/$name has no *.patch, skipped"
			continue
		fi

		MODULE_PATH=""
		MODULE_REPO=""
		MODULE_REF=""

		if [ -f "$dir/pin.env" ]; then
			# shellcheck disable=SC1091
			set -a
			source <(tr -d '\r' < "$dir/pin.env")
			set +a
		fi

		module_path="${MODULE_PATH:-}"
		repo="${MODULE_REPO:-$module_path}"
		ref="${MODULE_REF:-}"

		# 缺字段时回退到 go.mod
		if [ -z "$module_path" ] || [ -z "$ref" ]; then
			if ! entry="$(lookup_module "$name")"; then
				echo "::error::module '$name': no pin.env and not found in go.mod"
				exit 1
			fi
			IFS=$'\t' read -r gomod_path gomod_repo gomod_version <<<"$entry"
			module_path="${module_path:-$gomod_path}"
			repo="${MODULE_REPO:-${repo:-$gomod_repo}}"
			if [ -z "$ref" ]; then
				ref="${gomod_version##*-}"
				if ! [[ "$ref" =~ ^[0-9a-f]{12}$ ]]; then
					echo "::error::module '$name' is pinned to '$gomod_version' in go.mod; add patches/modules/$name/pin.env with MODULE_REF"
					exit 1
				fi
			fi
		fi

		[ -n "$module_path" ] || { echo "::error::module '$name': MODULE_PATH is empty"; exit 1; }
		[ -n "$repo" ] || { echo "::error::module '$name': MODULE_REPO is empty"; exit 1; }

		case "$repo" in
			http://*|https://*) repo_url="$repo" ;;
			*) repo_url="https://$repo" ;;
		esac

		module_dir="$ROOT/modules/$name"
		echo "::group::clone $repo_url@$ref"
		rm -rf "$module_dir"
		# 不要 blob 的克隆：既省流量，又能把分支/tag/缩写 SHA 统一解析成完整 SHA
		git clone -q --filter=blob:none --no-checkout "$repo_url" "$module_dir"
		full_sha="$(git -C "$module_dir" rev-parse --verify "${ref}^{commit}")"
		git -C "$module_dir" checkout -q --detach "$full_sha"
		echo "::endgroup::"

		apply_patches "$module_dir" "$name" "${files[@]}"

		( cd "$SRC_ABS" && go mod edit -replace "$module_path=$module_dir" )
		echo "::notice::replaced $module_path => $module_dir ($full_sha)"
	done
fi
