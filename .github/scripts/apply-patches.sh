#!/usr/bin/env bash
#
# 给 sing-box 源码和它依赖的 Go 模块打补丁。
#
#   patches/sing-box/*.patch         -> 打在 src/（sing-box 本体）
#   patches/*.patch                  -> 同上（旧的扁平放法，仍然支持）
#   patches/modules/<name>/*.patch   -> 打在 src/go.mod 里对应的模块上：
#                                       按 go.mod 的 require/replace 找到仓库和
#                                       commit，浅克隆到 modules/<name>，打完
#                                       补丁后用 go mod edit -replace 接进构建
#
# 用法：apply-patches.sh [src-dir]
#
# 例：给 eBPF 数据面库打补丁，就放 patches/modules/sing-ebpf/0001-xxx.patch
#     （模块名取 go.mod 里模块路径的最后一段）。

set -euo pipefail
shopt -s nullglob

SRC="${1:-src}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC_ABS="$ROOT/$SRC"

[ -d "$SRC_ABS" ] || { echo "::error::source directory not found: $SRC_ABS"; exit 1; }

apply_patches() {
	local target="$1" label="$2" files=()
	shift 2
	files=("$@")
	if [ ${#files[@]} -eq 0 ]; then
		return 0
	fi
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
# 从 go.mod 里找出 <name> 对应的 "模块路径 仓库 版本"，仓库即模块路径本身，
# 除非它有 replace 指向别处（例如 sagernet/sing => reF1nd/sing）。
lookup_module() {
	local name="$1" line old repo ver
	local gomod="$SRC_ABS/go.mod"

	# replace 行：replace A => B vX
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

	# require 行（含 require 块里的缩进行）
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

		entry="$(lookup_module "$name")" || {
			echo "::error::module '$name' not found in go.mod"
			exit 1
		}
		IFS=$'\t' read -r module_path repo version <<<"$entry"

		sha="${version##*-}"
		if ! [[ "$sha" =~ ^[0-9a-f]{12}$ ]]; then
			echo "::error::module '$name' is pinned to '$version', which is not a commit pseudo-version; cannot patch"
			exit 1
		fi

		module_dir="$ROOT/modules/$name"
		echo "::group::clone $repo@$sha"
		rm -rf "$module_dir"
		# 伪版本里只有 12 位缩写，GitHub 不接受按缩写 SHA fetch，
		# 所以做一次不要 blob 的克隆，用 rev-parse 还原完整 SHA。
		git clone -q --filter=blob:none --no-checkout "https://$repo" "$module_dir"
		full_sha="$(git -C "$module_dir" rev-parse --verify "${sha}^{commit}")"
		git -C "$module_dir" checkout -q --detach "$full_sha"
		echo "::endgroup::"

		apply_patches "$module_dir" "$name" "${files[@]}"

		( cd "$SRC_ABS" && go mod edit -replace "$module_path=$module_dir" )
		echo "::notice::replaced $module_path => $module_dir"
	done
fi
