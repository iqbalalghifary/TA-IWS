<!DOCTYPE html>
<html>
<head>
    <title>Cek Nama dalam PDF</title>
</head>
<body>
    <h1>Cek Nama dalam PDF</h1>

    <?php if (session()->has('validation')): ?>
        <div class="alert alert-danger">
            <?= session('validation')->listErrors() ?>
        </div>
    <?php endif; ?>

    <?php echo form_open_multipart('/cek-nama'); ?>
    <label for="pdf">Pilih File PDF:</label>
    <input type="file" name="pdf" accept=".pdf" required>
    <br>
    <button type="submit">Cek Nama</button>
    <?php echo form_close(); ?>
</body>
</html>
