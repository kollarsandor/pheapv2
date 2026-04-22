module compute

let sum_array (arr: []i64) : i64 =
  reduce (+) 0 arr

let map_add (arr: []i64) (value: i64) : []i64 =
  map (\x -> x + value) arr

let map_multiply (arr: []i64) (factor: i64) : []i64 =
  map (\x -> x * factor) arr

let filter_positive (arr: []i64) : []i64 =
  filter (\x -> x > 0) arr

let dot_product (a: []i64) (b: []i64) : i64 =
  reduce (+) 0 (map2 (*) a b)

let vector_add (a: []i64) (b: []i64) : []i64 =
  map2 (+) a b

let vector_sub (a: []i64) (b: []i64) : []i64 =
  map2 (-) a b

let vector_scale (arr: []i64) (scalar: i64) : []i64 =
  map (\x -> x * scalar) arr

let find_max (arr: []i64) : i64 =
  reduce i64.max (i64.lowest) arr

let find_min (arr: []i64) : i64 =
  reduce i64.min (i64.highest) arr

let count_positive (arr: []i64) : i64 =
  reduce (+) 0 (map (\x -> if x > 0 then 1 else 0) arr)

let sum_matrix (mat: [][]i64) : i64 =
  reduce (+) 0 (map (reduce (+) 0) mat)

let map_matrix (mat: [][]i64) (value: i64) : [][]i64 =
  map (map (\x -> x + value)) mat

let transpose (mat: [][]i64) : [][]i64 =
  transpose mat

let matrix_multiply (a: [][]i64) (b: [][]i64) : [][]i64 =
  let m = length a
  let n = length b
  let p = length (b[0])
  in map (\i ->
       map (\j ->
         reduce (+) 0 (map2 (\k a_ik -> a_ik * b[k][j]) (iota n) a[i])
       ) (iota p)
     ) (iota m)

let prefix_sum (arr: []i64) : []i64 =
  scan (+) 0 arr

let scatter (dest: []i64) (indices: []i64) (values: []i64) : []i64 =
  scatter dest indices values

let gather (src: []i64) (indices: []i64) : []i64 =
  map (\i -> src[i]) indices

let sort_array (arr: []i64) : []i64 =
  sorted arr

let reverse_array (arr: []i64) : []i64 =
  reverse arr

let partition_array (arr: []i64) (pivot: i64) : {left: []i64, right: []i64} =
  let left = filter (\x -> x <= pivot) arr
  let right = filter (\x -> x > pivot) arr
  in {left, right}

let histogram (arr: []i64) (num_bins: i64) : []i64 =
  let bin_size = (find_max arr - find_min arr + num_bins - 1) / num_bins
  let min_val = find_min arr
  in reduce (\acc x ->
       let bin = (x - min_val) / bin_size
       let clamped_bin = if bin >= num_bins then num_bins - 1 else bin
       let new_acc = acc with [clamped_bin] = acc[clamped_bin] + 1
       in new_acc
     ) (replicate num_bins 0) arr

let flatten_matrix (mat: [][]i64) : []i64 =
  flatten mat

let reshape_1d_to_2d (arr: []i64) (rows: i64) (cols: i64) : [][]i64 =
  reshape (rows, cols) arr

let flatten_3d (arr: [][][]i64) : []i64 =
  flatten (flatten arr)

let reshape_1d_to_3d (arr: []i64) (d1: i64) (d2: i64) (d3: i64) : [][][]i64 =
  reshape (d1, d2, d3) arr

let zip_arrays (a: []i64) (b: []i64) : [](i64, i64) =
  zip a b

let unzip_array (arr: [](i64, i64)) : {a: []i64, b: []i64} =
  unzip arr

let take_first (n: i64) (arr: []i64) : []i64 =
  take n arr

let drop_first (n: i64) (arr: []i64) : []i64 =
  drop n arr

let concatenate_arrays (a: []i64) (b: []i64) : []i64 =
  concat a b

let rotate_left (arr: []i64) (n: i64) : []i64 =
  rotate n arr

let rotate_right (arr: []i64) (n: i64) : []i64 =
  rotate (-n) arr

let all_equal (arr: []i64) : bool =
  let first = arr[0]
  in all (\x -> x == first) arr

let any_positive (arr: []i64) : bool =
  any (\x -> x > 0) arr

let all_positive (arr: []i64) : bool =
  all (\x -> x > 0) arr

let replicate_array (n: i64) (value: i64) : []i64 =
  replicate n value

let iota_array (n: i64) : []i64 =
  iota n

let update_array (arr: []i64) (index: i64) (value: i64) : []i64 =
  arr with [index] = value

let update_matrix (mat: [][]i64) (row: i64) (col: i64) (value: i64) : [][]i64 =
  mat with [row] = mat[row] with [col] = value

let slice_1d (arr: []i64) (start: i64) (len: i64) : []i64 =
  slice arr start len

let slice_2d (mat: [][]i64) (row_start: i64) (row_len: i64) (col_start: i64) (col_len: i64) : [][]i64 =
  map (\row -> slice row col_start col_len) (slice mat row_start row_len)

let mean_array (arr: []f64) : f64 =
  let n = f64.i64 (length arr)
  in reduce (+) 0.0 arr / n

let variance_array (arr: []f64) : f64 =
  let n = f64.i64 (length arr)
  let mean = mean_array arr
  in reduce (+) 0.0 (map (\x -> (x - mean) * (x - mean)) arr) / n

let std_dev_array (arr: []f64) : f64 =
  f64.sqrt (variance_array arr)

let normalize_array (arr: []f64) : []f64 =
  let mean = mean_array arr
  let std = std_dev_array arr
  in map (\x -> (x - mean) / std) arr

let min_max_normalize (arr: []f64) : []f64 =
  let min_val = reduce f64.min f64.highest arr
  let max_val = reduce f64.max f64.lowest arr
  let range = max_val - min_val
  in map (\x -> (x - min_val) / range) arr

let euclidean_distance (a: []f64) (b: []f64) : f64 =
  f64.sqrt (reduce (+) 0.0 (map (\x -> x * x) (map2 (-) a b)))

let cosine_similarity (a: []f64) (b: []f64) : f64 =
  let dot = reduce (+) 0.0 (map2 (*) a b)
  let mag_a = f64.sqrt (reduce (+) 0.0 (map (\x -> x * x) a))
  let mag_b = f64.sqrt (reduce (+) 0.0 (map (\x -> x * x) b))
  in dot / (mag_a * mag_b)

let softmax (arr: []f64) : []f64 =
  let max_val = reduce f64.max f64.lowest arr
  let exp_vals = map (\x -> f64.exp (x - max_val)) arr
  let sum_exp = reduce (+) 0.0 exp_vals
  in map (\x -> x / sum_exp) exp_vals

let relu (arr: []f64) : []f64 =
  map (\x -> if x > 0.0 then x else 0.0) arr

let sigmoid (arr: []f64) : []f64 =
  map (\x -> 1.0 / (1.0 + f64.exp (-x))) arr

let tanh_array (arr: []f64) : []f64 =
  map f64.tanh arr

let leaky_relu (arr: []f64) (alpha: f64) : []f64 =
  map (\x -> if x > 0.0 then x else alpha * x) arr

let elu (arr: []f64) (alpha: f64) : []f64 =
  map (\x -> if x > 0.0 then x else alpha * (f64.exp x - 1.0)) arr

let convolve_1d (signal: []f64) (kernel: []f64) : []f64 =
  let n = length signal
  let k = length kernel
  in map (\i ->
       reduce (+) 0.0 (map2 (\j s -> s * kernel[j]) (iota k) (slice signal i k))
     ) (iota (n - k + 1))

let moving_average (arr: []f64) (window: i64) : []f64 =
  let n = length arr
  in map (\i ->
       reduce (+) 0.0 (slice arr i window) / f64.i64 window
     ) (iota (n - window + 1))

let exponential_moving_average (arr: []f64) (alpha: f64) : []f64 =
  scan (\acc x -> alpha * x + (1.0 - alpha) * acc) arr[0] arr

let find_peaks (arr: []f64) (threshold: f64) : []i64 =
  let n = length arr
  in filter (\i ->
       i > 0 && i < n - 1 && arr[i] > arr[i-1] && arr[i] > arr[i+1] && arr[i] > threshold
     ) (iota n)
